#define pr_fmt(fmt) "%s[%25s]: " fmt, KBUILD_MODNAME, __func__

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/sock.h>

#include "xwall.h"

// #define BENCHMARK

#ifdef BENCHMARK
#define XWALL_PR_INFO(...)
#else
#define XWALL_PR_INFO(...) pr_info(__VA_ARGS__)
#endif

#define IS_SYN(tcp)             ((tcp_flag_word(tcp) & TCP_FLAG_SYN) != 0)
#define IS_ECHO_REQUEST(icmp)   (icmp->type == ICMP_ECHO && icmp->code == 0)
#define ktime_cur_before(kt)    (ktime_before(ktime_get_real(), (kt)))
#define ktime_add_sec(kt, sval) (ktime_add_ns((kt), (sval)*NSEC_PER_SEC))

#ifdef BENCHMARK
static bool default_logging = false;
#else
static bool default_logging = true;
#endif
static unsigned int default_action        = NF_DROP;
static int default_timeout_tcp            = 300;
static int default_timeout_udp            = 180;
static int default_timeout_icmp           = 180;
static int default_timeout_others         = 180;
static struct sock *nl_sk                 = NULL;
static struct xwall_logtable *log_table   = NULL;
static struct xwall_mlogtable *mlog_table = NULL;
static struct xwall_hashtable *conn_table = NULL;
static struct xwall_ruletable *rule_table = NULL;
static struct xwall_nat nat_table[XWALL_MAX_NAT_ENTRY_NUM];

static __be16 nat_port     = XWALL_NAT_PORT_START;
static int nat_timeout_sec = 60;
static __be32 ip_lan_mask  = ip_to_be32(255, 255, 255, 0);
static __be32 ip_wan_mask  = ip_to_be32(255, 255, 255, 0);
static __be32 xwall_ip_lan = ip_to_be32(192, 168, 44, 1);
static __be32 xwall_ip_wan = ip_to_be32(10, 0, 12, 2);

static struct timer_list conn_timer;

static const struct nf_hook_ops nf_xwall_ops[] = {
    // {
    //     .hook     = xwall_filter,
    //     .pf       = PF_INET,
    //     .hooknum  = NF_INET_PRE_ROUTING,
    //     .priority = NF_IP_PRI_LAST,
    // },
    {
        .hook     = xwall_filter,
        .pf       = PF_INET,
        .hooknum  = NF_INET_FORWARD,
        .priority = NF_IP_PRI_FIRST,
    },
    // {
    //     .hook     = xwall_filter,
    //     .pf       = PF_INET,
    //     .hooknum  = NF_INET_POST_ROUTING,
    //     .priority = NF_IP_PRI_FIRST,
    // },
    {
        .hook     = xwall_nat_in,
        .pf       = PF_INET,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_NAT_DST,
    },
    {
        .hook     = xwall_nat_out,
        .pf       = PF_INET,
        .hooknum  = NF_INET_POST_ROUTING,
        .priority = NF_IP_PRI_NAT_SRC,
    },
};

/* UTILES */
void xwall_show_packet(struct iphdr *iph)
{
    switch (iph->protocol) {
    case IPPROTO_TCP:
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + iph->ihl * 4);
        XWALL_PR_INFO("TCP: %pI4,%d > %pI4,%d\n", &iph->saddr,
                      ntohs(tcph->source), &iph->daddr, ntohs(tcph->dest));
        break;
    case IPPROTO_UDP:
        struct udphdr *udph = (struct udphdr *)((char *)iph + iph->ihl * 4);
        XWALL_PR_INFO("UDP: %pI4,%d > %pI4,%d\n", &iph->saddr,
                      ntohs(udph->source), &iph->daddr, ntohs(udph->dest));
        break;
    case IPPROTO_ICMP:
        struct icmphdr *icmph = (struct icmphdr *)((char *)iph + iph->ihl * 4);
        XWALL_PR_INFO("ICMP: %pI4 > %pI4, type=%d, code=%d\n", &iph->saddr,
                      &iph->daddr, icmph->type, icmph->code);
        break;
    default:
        XWALL_PR_INFO("Unknown protocol: %d", iph->protocol);
    }
}

void xwall_timer_callback(struct timer_list *t)
{
    XWALL_PR_INFO("Clean the connection table...");
    xwall_hashtable_clean(conn_table);
    conn_timer.expires = jiffies + XWALL_CLEAN_CONN_INVERVAL_SEC * HZ;
    add_timer(&conn_timer);
}

/* CONNECTION TABLE */
struct xwall_index *xwall_index_create(struct iphdr *iph)
{
    struct xwall_index *idx = kvzalloc(sizeof(*idx), GFP_KERNEL);
    if (!idx)
        return NULL;

    idx->saddr    = iph->saddr;
    idx->daddr    = iph->daddr;
    idx->protocol = iph->protocol;
    switch (iph->protocol) {
    case IPPROTO_TCP:
        struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
        idx->sport          = tcph->source;
        idx->dport          = tcph->dest;
        break;
    case IPPROTO_UDP:
        struct udphdr *udph = (void *)iph + iph->ihl * 4;
        idx->sport          = udph->source;
        idx->dport          = udph->dest;
        break;
    case IPPROTO_ICMP:
    default:
        idx->sport = idx->dport = 0x0;
    }

    return idx;
}

struct xwall_connection *xwall_connection_create(struct iphdr *iph)
{
    struct xwall_connection *conn = kvzalloc(sizeof(*conn), GFP_KERNEL);
    if (!conn)
        return NULL;

    conn->saddr    = iph->saddr;
    conn->daddr    = iph->daddr;
    conn->protocol = iph->protocol;
    switch (iph->protocol) {
    case IPPROTO_TCP:
        struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
        conn->tcp.sport     = tcph->source;
        conn->tcp.dport     = tcph->dest;
        conn->timeout =
            htonll(ktime_add_sec(ktime_get_real(), default_timeout_tcp));
        break;
    case IPPROTO_UDP:
        struct udphdr *udph = (void *)iph + iph->ihl * 4;
        conn->udp.sport     = udph->source;
        conn->udp.dport     = udph->dest;
        conn->timeout =
            htonll(ktime_add_sec(ktime_get_real(), default_timeout_udp));
        break;
    case IPPROTO_ICMP:
        struct icmphdr *icmph = (void *)iph + iph->ihl * 4;
        conn->icmp.type       = icmph->type;
        conn->icmp.code       = icmph->code;
        conn->timeout =
            htonll(ktime_add_sec(ktime_get_real(), default_timeout_icmp));
        break;
    default:
        conn->timeout =
            htonll(ktime_add_sec(ktime_get_real(), default_timeout_others));
    }

    return conn;
}

struct xwall_hashtable *xwall_hashtable_create(void)
{
    struct xwall_hashtable *table = kvzalloc(sizeof(*table), GFP_KERNEL);
    if (!table)
        return NULL;

    hash_init(table->hashtable);
    rwlock_init(&table->lock);
    return table;
}

void xwall_hashtable_add(struct xwall_hashtable *table,
                         struct xwall_connection *conn, struct xwall_index *idx)
{
    u32 hashv;
    XWALL_HASH_JEN(idx, sizeof(idx), hashv, HASH_BITS(table->hashtable));

    write_lock(&table->lock);
    table->conn_num++;
    /* Use default hash function, need the sizeof(idx) <= 8. */
    // u64 idx_64 = *((u64 *)(&idx));
    // hash_add(table->hashtable, &conn->node, idx_64);

    /* Use custom hash function (Jenkins), need the sizeof(idx) == 12n. */
    hlist_add_head(&conn->node, &(table->hashtable)[hashv]);
    write_unlock(&table->lock);
}

void xwall_hashtable_del(struct xwall_hashtable *table,
                         struct xwall_connection *conn)
{
    write_lock(&table->lock);
    hash_del(&conn->node);
    kfree(conn);
    write_unlock(&table->lock);
}

bool _xwall_hashtable_match(struct xwall_hashtable *table,
                            struct xwall_connection *conn,
                            struct xwall_index *idx, bool reverse)
{
    u32 hashv;
    bool res = false;
    struct xwall_connection *cur_conn;

    if (reverse) {
        swap(idx->saddr, idx->daddr);
        swap(idx->sport, idx->dport);
        swap(conn->saddr, conn->daddr);
    }
    XWALL_HASH_JEN(idx, sizeof(idx), hashv, HASH_BITS(table->hashtable));

    read_lock(&table->lock);
    hlist_for_each_entry(cur_conn, &(table->hashtable)[hashv], node)
    {
        if (conn->protocol == IPPROTO_TCP) {
            if (reverse)
                swap(conn->tcp.sport, conn->tcp.dport);
            res = existing_connection_tcp(cur_conn, conn);
            if (reverse)
                swap(conn->tcp.sport, conn->tcp.dport);
            // XWALL_PR_INFO("reverse: %d, res = %d", reverse, res);
            // XWALL_PR_INFO("old: %pI4 %pI4 %d %d", &cur_conn->saddr,
            // &cur_conn->daddr,
            //         ntohs(cur_conn->tcp.sport), ntohs(cur_conn->tcp.dport));
            // XWALL_PR_INFO("new: %pI4 %pI4 %d %d", &conn->saddr, &conn->daddr,
            //         ntohs(conn->tcp.sport), ntohs(conn->tcp.dport));
        } else if (conn->protocol == IPPROTO_UDP) {
            if (reverse)
                swap(conn->udp.sport, conn->udp.dport);
            // XWALL_PR_INFO("cur:  %pI4,%d => %pI4,%d", &cur_conn->saddr,
            //         cur_conn->udp.sport, &cur_conn->daddr,
            //         cur_conn->udp.dport);
            // XWALL_PR_INFO("conn: %pI4,%d => %pI4,%d", &conn->saddr,
            // conn->udp.sport,
            //         &conn->daddr, conn->udp.dport);
            res = (cur_conn->saddr == conn->saddr &&
                   cur_conn->daddr == conn->daddr &&
                   cur_conn->udp.sport == conn->udp.sport &&
                   cur_conn->udp.dport == conn->udp.dport);
            if (reverse)
                swap(conn->udp.sport, conn->udp.dport);
        } else if (conn->protocol == IPPROTO_ICMP) {
            // XWALL_PR_INFO("cur_conn: %pI4 > %pI4", &cur_conn->saddr,
            //         &cur_conn->daddr);
            // XWALL_PR_INFO("conn    : %pI4 > %pI4", &conn->saddr,
            // &conn->daddr); res = existing_connection_icmp(cur_conn, conn);
            if (reverse) {
                res = cur_conn->saddr == conn->saddr &&
                      cur_conn->daddr == conn->daddr &&
                      cur_conn->icmp.type == ICMP_ECHO &&
                      cur_conn->icmp.code == 0 &&
                      conn->icmp.type == ICMP_ECHOREPLY && conn->icmp.code == 0;
            } else {
                res = cur_conn->saddr == conn->saddr &&
                      cur_conn->daddr == conn->daddr &&
                      cur_conn->icmp.type == ICMP_ECHO &&
                      cur_conn->icmp.code == 0 &&
                      conn->icmp.type == ICMP_ECHO && conn->icmp.code == 0;
            }

        } else {
            res = existing_connection_others(cur_conn, conn);
        }
        if (res) {
            if (ktime_cur_before((ktime_t)ntohll(cur_conn->timeout))) {
                switch (cur_conn->protocol) {
                case IPPROTO_ICMP:
                    cur_conn->timeout = htonll(
                        ktime_add_sec(ktime_get_real(), default_timeout_icmp));
                    break;
                case IPPROTO_UDP:
                    cur_conn->timeout = htonll(
                        ktime_add_sec(ktime_get_real(), default_timeout_udp));
                    break;
                case IPPROTO_TCP:
                    cur_conn->timeout = htonll(
                        ktime_add_sec(ktime_get_real(), default_timeout_tcp));
                    break;
                default:
                    cur_conn->timeout = htonll(ktime_add_sec(
                        ktime_get_real(), default_timeout_others));
                }
                break;
            } else {
                res = false;
            }
        }
    }
    read_unlock(&table->lock);

    if (reverse) {
        swap(idx->saddr, idx->daddr);
        swap(idx->sport, idx->dport);
        swap(conn->saddr, conn->daddr);
    }

    return res;
}

bool xwall_hashtable_match(struct xwall_hashtable *table,
                           struct xwall_connection *conn,
                           struct xwall_index *idx)
{
    bool res = false;

    if (conn->protocol == IPPROTO_TCP) {
        res = _xwall_hashtable_match(table, conn, idx, false) ||
              _xwall_hashtable_match(table, conn, idx, true);
    } else if (conn->protocol == IPPROTO_UDP) {
        res = _xwall_hashtable_match(table, conn, idx, false) ||
              _xwall_hashtable_match(table, conn, idx, true);
    } else if (conn->protocol == IPPROTO_ICMP) {
        res = _xwall_hashtable_match(table, conn, idx, false) ||
              _xwall_hashtable_match(table, conn, idx, true);
    } else {
        res = _xwall_hashtable_match(table, conn, idx, true);
    }

    return res;
}

char *xwall_hashtable_read(struct xwall_hashtable *table, int *len)
{
    char *buff                    = NULL;
    int i                         = 0;
    int hashv                     = 0;
    struct xwall_connection *conn = NULL;
    __be32 conn_num               = htonl(table->conn_num);

    *len = sizeof(unsigned int) + sizeof(struct xwall_rule) * table->conn_num;
    buff = (char *)kvzalloc(*len, GFP_KERNEL);
    if (!buff)
        return NULL;

    read_lock(&table->lock);
    memcpy(buff, &conn_num, sizeof(unsigned int));
    for (; hashv < HASH_SIZE(table->hashtable); hashv++) {
        hlist_for_each_entry(conn, &(table->hashtable)[hashv], node)
        {
            memcpy(buff + sizeof(unsigned int) +
                       sizeof(struct xwall_connection) * i,
                   conn, sizeof(struct xwall_connection));
            i++;
        }
    }
    read_unlock(&table->lock);

    return buff;
}

void xwall_hashtable_clean(struct xwall_hashtable *table)
{
    int i;
    struct hlist_node *tmp        = NULL;
    struct xwall_connection *conn = NULL;

    write_lock(&table->lock);
    for (i = 0; i < HASH_SIZE(table->hashtable); ++i) {
        hlist_for_each_entry_safe(conn, tmp, &(table->hashtable)[i], node)
        {
            if (!ktime_cur_before(ntohll(conn->timeout))) {
                switch (conn->protocol) {
                case IPPROTO_TCP:
                    XWALL_PR_INFO("Delete connection: [TCP] %pI4,%d > %pI4,%d",
                                  &conn->saddr, ntohs(conn->tcp.sport),
                                  &conn->daddr, ntohs(conn->tcp.dport));
                    break;
                case IPPROTO_UDP:
                    XWALL_PR_INFO("Delete connection: [UDP] %pI4,%d > %pI4,%d",
                                  &conn->saddr, ntohs(conn->udp.sport),
                                  &conn->daddr, ntohs(conn->udp.dport));
                    break;
                case IPPROTO_ICMP:
                    XWALL_PR_INFO("Delete connection: [ICMP] %pI4 > %pI4",
                                  &conn->saddr, &conn->daddr);
                    break;
                default:
                }
                hash_del(&conn->node);
                kfree(conn);
                table->conn_num--;
            }
        }
    }
    write_unlock(&table->lock);
}

void xwall_hashtable_clear(struct xwall_hashtable *table)
{
    unsigned int i;
    struct hlist_node *tmp        = NULL;
    struct xwall_connection *conn = NULL;

    write_lock(&table->lock);
    table->conn_num = 0;
    for (i = 0; i < HASH_SIZE(table->hashtable); ++i) {
        hlist_for_each_entry_safe(conn, tmp, &(table->hashtable)[i], node)
        {
            hash_del(&conn->node);
            kfree(conn);
        }
    }
    hash_init(table->hashtable);
    write_unlock(&table->lock);
}

/* RULE TABLE */
struct xwall_ruletable *xwall_ruletable_create(void)
{
    struct xwall_ruletable *rule_table =
        kvzalloc(sizeof(*rule_table), GFP_KERNEL);
    if (!rule_table)
        return NULL;

    INIT_LIST_HEAD(&rule_table->node);
    rwlock_init(&rule_table->lock);
    return rule_table;
}

void xwall_ruletable_add(struct xwall_ruletable *table, struct xwall_rule *rule)
{
    struct xwall_mlog *mlog = xwall_mlog_create();
    sprintf(mlog->msg,
            "Add Rule: %pI4,%d~%d(%pI4) > %pI4,%d~%d(%pI4) protocol[%d] "
            "logging[%d] action[%d]",
            &rule->saddr, ntohs(rule->sport_min), ntohs(rule->sport_max),
            &rule->smask, &rule->daddr, ntohs(rule->dport_min),
            ntohs(rule->dport_max), &rule->dmask, rule->protocol, rule->logging,
            ntohl(rule->action));
    xwall_mlogtable_add(mlog_table, mlog);

    write_lock(&table->lock);
    rule->idx = htonl(table->rule_num);
    list_add_tail(&rule->node, &table->node);
    table->rule_num++;
    write_unlock(&table->lock);
}

void xwall_ruletable_del(struct xwall_ruletable *table, struct xwall_rule *rule)
{
    write_lock(&table->lock);
    list_del(&rule->node);
    kfree(rule);
    // table->rule_num--;
    write_unlock(&table->lock);
}

bool xwall_ruletable_del_by_idx(struct xwall_ruletable *table, unsigned int idx)
{
    bool ret                = false;
    struct xwall_rule *rule = NULL;
    struct xwall_mlog *mlog = NULL;

    write_lock(&table->lock);
    list_for_each_entry(rule, &(table->node), node)
    {
        if ((unsigned int)ntohl(rule->idx) == idx) {
            mlog = xwall_mlog_create();
            sprintf(mlog->msg,
                    "Delete Rule: %pI4,%d~%d(%pI4) > %pI4,%d~%d(%pI4) "
                    "protocol[%d] logging[%d] action[%d]",
                    &rule->saddr, ntohs(rule->sport_min),
                    ntohs(rule->sport_max), &rule->smask, &rule->daddr,
                    ntohs(rule->dport_min), ntohs(rule->dport_max),
                    &rule->dmask, rule->protocol, rule->logging,
                    ntohl(rule->action));
            xwall_mlogtable_add(mlog_table, mlog);
            list_del(&rule->node);
            kfree(rule);
            ret = true;
            break;
        }
    }
    write_unlock(&table->lock);
    return ret;
}

struct xwall_rule *xwall_ruletable_match(struct xwall_ruletable *table,
                                         struct xwall_connection *conn)
{
    // TODO: how to use the mask.
    bool flag               = false;
    struct xwall_rule *rule = NULL;

    read_lock(&table->lock);
    list_for_each_entry(rule, &(table->node), node)
    {
        if (!(conn->protocol == rule->protocol &&
              (conn->saddr & rule->smask) == (rule->saddr & rule->smask) &&
              (conn->daddr & rule->dmask) == (rule->daddr & rule->dmask) &&
              ktime_cur_before((ktime_t)ntohll(rule->timeout)))) {
            continue;
        }
        switch (conn->protocol) {
        case IPPROTO_TCP:
            flag = conn->tcp.sport >= rule->sport_min &&
                   conn->tcp.sport <= rule->sport_max &&
                   conn->tcp.dport >= rule->dport_min &&
                   conn->tcp.dport <= rule->dport_max;
            break;
        case IPPROTO_UDP:
            flag = conn->udp.sport >= rule->sport_min &&
                   conn->udp.sport <= rule->sport_max &&
                   conn->udp.dport >= rule->dport_min &&
                   conn->udp.dport <= rule->dport_max;
            break;
        case IPPROTO_ICMP:
            flag = true;
            break;
        default:
            flag = true;
        }
        if (flag)
            break;
    }
    read_unlock(&table->lock);

    return flag ? rule : NULL;
}

char *xwall_ruletable_read(struct xwall_ruletable *table,
                           unsigned int start_idx, unsigned int end_idx,
                           int *len)
{
    char *buff              = NULL;
    unsigned int cur_idx    = 0;
    struct xwall_rule *rule = NULL;
    __be32 rule_num         = htonl(table->rule_num);

    *len = sizeof(unsigned int) +
           sizeof(struct xwall_rule) * (end_idx - start_idx);
    buff = (char *)kvzalloc(*len, GFP_KERNEL);
    if (!buff)
        return NULL;

    read_lock(&table->lock);
    memcpy(buff, &rule_num, sizeof(unsigned int));
    list_for_each_entry(rule, &(table->node), node)
    {
        cur_idx = (unsigned int)ntohl(rule->idx);
        if (cur_idx < start_idx) {
            continue;
        } else if (cur_idx >= end_idx) {
            break;
        } else {
            memcpy(buff + sizeof(unsigned int) +
                       sizeof(struct xwall_rule) * (cur_idx - start_idx),
                   rule, sizeof(struct xwall_rule));
        }
    }
    read_unlock(&table->lock);

    return buff;
}

int xwall_ruletable_real_num(struct xwall_ruletable *table)
{
    int ret                 = 0;
    struct xwall_rule *rule = NULL;

    /* Write lock. */
    write_lock(&table->lock);
    list_for_each_entry(rule, &(table->node), node) ret++;
    write_unlock(&table->lock);

    return ret;
}

bool xwall_save_rule(struct xwall_ruletable *table)
{
    int len    = 0;
    int ret    = 0;
    __u8 *buff = NULL;
    struct file *fp;

    /* Open/Create file. */
    fp = filp_open(XWALL_RULE_FILE, O_RDWR | O_CREAT, XWALL_RULE_FILE_PRIV);
    if (IS_ERR(fp)) {
        pr_err("Open rule file error.\n");
        return false;
    }

    /* Copy rules to buffer. */
    buff =
        xwall_ruletable_read(table, 0, xwall_ruletable_real_num(table), &len);
    // buff = xwall_ruletable_read(table, 0, table->rule_num, &len);
    if (!buff) {
        pr_err("Read rule error.\n");
        ret = false;
        goto out;
    }

    /* Write rules to file. */
    ret = kernel_write(fp, buff + sizeof(unsigned int),
                       len - sizeof(unsigned int), &fp->f_pos);
    if (ret < 0) {
        pr_err("Write rules to file error %d.\n", ret);
        ret = false;
        goto out;
    }

    ret = true;
    XWALL_PR_INFO("Write rule to file " XWALL_RULE_FILE " done.\n");

out:
    kfree(buff);
    filp_close(fp, NULL);

    return ret;
}

bool xwall_load_rule(struct xwall_ruletable *table)
{
    int i      = 0;
    int ret    = 0;
    loff_t pos = 0;
    struct xwall_rule rule, zero_rule = {0};
    struct file *fp;
    struct xwall_rule *rule_heap;

    /* Open/Create file. */
    fp = filp_open(XWALL_RULE_FILE, O_RDWR, XWALL_RULE_FILE_PRIV);
    if (IS_ERR(fp)) {
        pr_err("Open rule file error.\n");
        return false;
    }

    /* Read rules and add. */
    while (kernel_read(fp, (__u8 *)&rule, sizeof(rule), &pos) == sizeof(rule)) {
        if (memcmp(&zero_rule, &rule, sizeof(rule))) {
            rule_heap = kvzalloc(sizeof(*rule_heap), GFP_KERNEL);
            memcpy(rule_heap, &rule, sizeof(rule));
            rule_heap->idx = htonl(i++);
            xwall_ruletable_add(table, rule_heap);
        }
    }

    ret = true;
    XWALL_PR_INFO("Add %d rule from file " XWALL_RULE_FILE " done.\n", i);
    filp_close(fp, NULL);

    return ret;
}

void xwall_ruletable_clear(struct xwall_ruletable *table)
{
    struct xwall_rule *rule = NULL, *tmp = NULL;

    write_lock(&table->lock);
    list_for_each_entry_safe(rule, tmp, &(table->node), node)
    {
        list_del(&rule->node);
        kfree(rule);
    }
    table->rule_num = 0;
    INIT_LIST_HEAD(&rule_table->node);
    write_unlock(&table->lock);
}

/* LOG */
struct xwall_log *xwall_log_create(struct sk_buff *skb, unsigned int action)
{
    struct iphdr *iph     = ip_hdr(skb);
    struct xwall_log *log = kvzalloc(sizeof(*log), GFP_KERNEL);
    if (!log)
        return NULL;

    log->ts       = htonll(ktime_get_real());
    log->saddr    = iph->saddr;
    log->daddr    = iph->daddr;
    log->protocol = iph->protocol;
    log->len      = iph->tot_len;
    log->action   = htonl(action);
    switch (iph->protocol) {
    case IPPROTO_TCP:
        struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
        log->tcp.sport      = tcph->source;
        log->tcp.dport      = tcph->dest;
        break;
    case IPPROTO_UDP:
        struct udphdr *udph = (void *)iph + iph->ihl * 4;
        log->udp.sport      = udph->source;
        log->udp.dport      = udph->dest;
        break;
    case IPPROTO_ICMP:
        struct icmphdr *icmph = (void *)iph + iph->ihl * 4;
        log->icmp.type        = icmph->type;
        log->icmp.code        = icmph->code;
        break;
    default:
    }

    return log;
}

struct xwall_logtable *xwall_logtable_create(void)
{
    struct xwall_logtable *log_table = kvzalloc(sizeof(*log_table), GFP_KERNEL);
    if (!log_table)
        return NULL;

    INIT_LIST_HEAD(&log_table->node);
    mutex_init(&log_table->lock);
    return log_table;
}

void xwall_logtable_add(struct xwall_logtable *table, struct xwall_log *log)
{
    mutex_lock(&table->lock);
    log->idx = htonl(table->log_num);
    list_add_tail(&log->node, &table->node);
    table->log_num++;
    mutex_unlock(&table->lock);
}

char *xwall_logtable_read(struct xwall_logtable *table, unsigned int start_idx,
                          unsigned int end_idx, int *len)
{
    char *buff            = NULL;
    unsigned int cur_idx  = 0;
    struct xwall_log *log = NULL;
    __be32 log_num        = htonl(table->log_num);

    *len =
        sizeof(unsigned int) + sizeof(struct xwall_log) * (end_idx - start_idx);
    buff = (char *)kvzalloc(*len, GFP_KERNEL);
    if (!buff)
        return NULL;

    mutex_lock(&table->lock);
    memcpy(buff, &log_num, sizeof(unsigned int));
    list_for_each_entry(log, &(table->node), node)
    {
        cur_idx = (unsigned int)ntohl(log->idx);
        if (cur_idx < start_idx) {
            continue;
        } else if (cur_idx >= end_idx) {
            break;
        } else {
            memcpy(buff + sizeof(unsigned int) +
                       sizeof(struct xwall_log) * (cur_idx - start_idx),
                   log, sizeof(struct xwall_log));
        }
    }
    mutex_unlock(&table->lock);

    return buff;
}

void xwall_logtable_clear(struct xwall_logtable *table)
{
    struct xwall_log *log = NULL, *tmp = NULL;

    mutex_lock(&table->lock);
    list_for_each_entry_safe(log, tmp, &(table->node), node)
    {
        list_del(&log->node);
        kfree(log);
    }
    table->log_num = 0;
    INIT_LIST_HEAD(&log_table->node);
    mutex_unlock(&table->lock);
}

/* MANAGE LOG */
struct xwall_mlog *xwall_mlog_create(void)
{
    struct xwall_mlog *mlog = kvzalloc(sizeof(*mlog), GFP_KERNEL);
    if (!mlog)
        return NULL;

    mlog->ts = htonll(ktime_get_real());
    return mlog;
}

struct xwall_mlogtable *xwall_mlogtable_create(void)
{
    struct xwall_mlogtable *mlog_table =
        kvzalloc(sizeof(*mlog_table), GFP_KERNEL);
    if (!mlog_table)
        return NULL;

    INIT_LIST_HEAD(&mlog_table->node);
    mutex_init(&mlog_table->lock);
    return mlog_table;
}

void xwall_mlogtable_add(struct xwall_mlogtable *table, struct xwall_mlog *mlog)
{
    mutex_lock(&table->lock);
    mlog->idx = htonl(table->log_num);
    list_add_tail(&mlog->node, &table->node);
    table->log_num++;
    mutex_unlock(&table->lock);
}

char *xwall_mlogtable_read(struct xwall_mlogtable *table,
                           unsigned int start_idx, unsigned int end_idx,
                           int *len)
{
    char *buff              = NULL;
    unsigned int cur_idx    = 0;
    struct xwall_mlog *mlog = NULL;
    __be32 log_num          = htonl(table->log_num);

    *len = sizeof(unsigned int) +
           sizeof(struct xwall_mlog) * (end_idx - start_idx);
    buff = (char *)kvzalloc(*len, GFP_KERNEL);
    if (!buff)
        return NULL;

    mutex_lock(&table->lock);
    memcpy(buff, &log_num, sizeof(unsigned int));
    list_for_each_entry(mlog, &(table->node), node)
    {
        cur_idx = (unsigned int)ntohl(mlog->idx);
        if (cur_idx < start_idx) {
            continue;
        } else if (cur_idx >= end_idx) {
            break;
        } else {
            memcpy(buff + sizeof(unsigned int) +
                       sizeof(struct xwall_mlog) * (cur_idx - start_idx),
                   mlog, sizeof(struct xwall_mlog));
        }
    }
    mutex_unlock(&table->lock);

    return buff;
}

void xwall_mlogtable_clear(struct xwall_mlogtable *table)
{
    struct xwall_mlog *mlog = NULL, *tmp = NULL;

    mutex_lock(&table->lock);
    list_for_each_entry_safe(mlog, tmp, &(table->node), node)
    {
        list_del(&mlog->node);
        kfree(mlog);
    }
    table->log_num = 0;
    INIT_LIST_HEAD(&log_table->node);
    mutex_unlock(&table->lock);
}

/* NAT */
__be16 xwall_nattable_match(__be32 saddr, __be16 sport)
{
    int i = 0;
    for (i = 0; i < XWALL_MAX_NAT_ENTRY_NUM; i++) {
        if ((nat_table[i].lan_addr == saddr) &&
            (nat_table[i].lan_port == sport) && nat_table[i].valid) {
            if (!ktime_cur_before(nat_table[i].timeout)) {
                XWALL_PR_INFO("NAT entry with port %d timeout\n", i);
                nat_table[i].valid = false;
                return 0;
            }
            return i;
        }
    }
    return 0;
}

void xwall_update_checksum_ip(struct iphdr *iph)
{
    if (!iph)
        return;

    iph->check = 0;
    iph->check = ip_fast_csum((__u8 *)iph, iph->ihl);
}

void xwall_update_checksum_tcp(struct sk_buff *skb, struct tcphdr *tcph,
                               struct iphdr *iph)
{
    int tcp_len = 0;
    if (!skb || !iph || !tcph)
        return;
    tcp_len = skb->len - 4 * iph->ihl;

    tcph->check = 0;
    tcph->check =
        csum_tcpudp_magic(iph->saddr, iph->daddr, tcp_len, IPPROTO_TCP,
                          csum_partial(tcph, tcp_len, 0));
}

void xwall_update_checksum_udp(struct sk_buff *skb, struct udphdr *udph,
                               struct iphdr *iph)
{
    int udp_len = 0;
    if (!skb || !iph || !udph)
        return;
    udp_len = skb->len - 4 * iph->ihl;

    udph->check = 0;
    udph->check =
        csum_tcpudp_magic(iph->saddr, iph->daddr, udp_len, IPPROTO_UDP,
                          csum_partial(udph, udp_len, 0));
}

void xwall_update_checksum_icmp(struct sk_buff *skb, struct icmphdr *icmph,
                                struct iphdr *iph)
{
    int icmp_len = 0;
    if (!skb || !iph || !icmph)
        return;
    icmp_len = skb->len - 4 * iph->ihl;

    icmph->checksum = 0;
    icmph->checksum = csum_fold(csum_partial(icmph, icmp_len, 0));
}

/* NETLINK */
struct xwall_response *xwall_response_create(enum XWALL_RESPONSE_TYPE type,
                                             int len, char *data)
{
    struct xwall_response *resp = kvzalloc(sizeof(*resp) + len, GFP_KERNEL);
    if (!resp)
        return NULL;

    resp->type = type;
    resp->len  = htonl(len);
    memcpy(resp->msg, data, len);

    return resp;
}

int xwall_netlink_send(int pid, char *data, int len)
{
    int ret;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    skb = nlmsg_new(len, GFP_ATOMIC);
    if (skb == NULL) {
        pr_err("Alloc reply nlmsg skb failed!\n");
        return -ENOMEM;
    }

    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
    memcpy(NLMSG_DATA(nlh), data, len);

    // NETLINK_CB(skb).pid = 0;
    NETLINK_CB(skb).dst_group = 0;

    ret = netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT);
    XWALL_PR_INFO("Data send to user %d.\n", pid);
    return ret;
}

int xwall_msg_hdr(int pid, char *data, int len)
{
    /* TODO: if operation failed, reply the wrong message. */
    int ret = 0, data_len = 0;
    char *buff_heap = NULL, *buff = NULL;
    struct xwall_response *resp = NULL;
    struct xwall_request *req   = (struct xwall_request *)data;
    struct xwall_mlog *mlog     = xwall_mlog_create();

    /* Manage Log. */
    switch (req->opcode) {
    case XWALL_OP_ADDRULE:
        sprintf(mlog->msg, "Add rule from user netlink.");
        break;
    case XWALL_OP_DELRULE:
        sprintf(mlog->msg, "Delete rule from user netlink.");
        break;
    case XWALL_OP_READRULE:
        sprintf(mlog->msg, "Read rule from user netlink.");
        break;
    case XWALL_OP_SAVERULE:
        sprintf(mlog->msg, "Save rule from user netlink.");
        break;
    case XWALL_OP_READLOG:
        sprintf(mlog->msg, "Read log from user netlink.");
        break;
    case XWALL_OP_CLRLOG:
        sprintf(mlog->msg, "Clear log from user netlink.");
        break;
    case XWALL_OP_READMLOG:
        sprintf(mlog->msg, "Read manage log from user netlink.");
        break;
    case XWALL_OP_READCONN:
        sprintf(mlog->msg, "Read connect from user netlink.");
        break;
    case XWALL_OP_CLRMLOG:
        sprintf(mlog->msg, "Clear manage log from user netlink.");
        break;
    case XWALL_OP_DEFACT:
        sprintf(mlog->msg, "Set default action from user netlink.");
        break;
    case XWALL_OP_READDEFACT:
        sprintf(mlog->msg, "Read default action from user netlink.");
        break;
    default:
        sprintf(mlog->msg, "Unknown message from user netlink.");
    }
    xwall_mlogtable_add(mlog_table, mlog);

    /* Do things. */
    switch (req->opcode) {
    case XWALL_OP_ADDRULE:
        struct xwall_rule *rule = kvzalloc(sizeof(*rule), GFP_KERNEL);
        memcpy(rule, &req->msg.rule_add, sizeof(*rule));
        rule->timeout = htonll(ktime_add_sec(ktime_get_real(), 3600 * 24));
        xwall_ruletable_add(rule_table, rule);
        buff     = "Add rule success!";
        data_len = strlen(buff);
        resp     = xwall_response_create(XWALL_TYPE_OK, data_len, buff);
        if (!resp) {
            pr_err("[ADDRULE] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_DELRULE:
        bool del_ret = xwall_ruletable_del_by_idx(rule_table,
                                                  ntohl(req->msg.rule_del_idx));
        xwall_hashtable_clear(conn_table);
        buff     = del_ret ? "Delete rule success!" : "No such rule!";
        data_len = strlen(buff);
        resp = xwall_response_create(del_ret ? XWALL_TYPE_OK : XWALL_TYPE_ERROR,
                                     data_len, buff);
        if (!resp) {
            pr_err("[DELRULE] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_READRULE:
        buff_heap = xwall_ruletable_read(
            rule_table, ntohl(req->msg.read_rule.start_idx),
            ntohl(req->msg.read_rule.end_idx), &data_len);
        if (!buff_heap) {
            pr_err("[READRULE] Log buffer create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        resp = xwall_response_create(XWALL_TYPE_RULE, data_len, buff_heap);
        if (!resp) {
            pr_err("[READRULE] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_SAVERULE:
        ret      = xwall_save_rule(rule_table);
        buff     = ret ? "Save rules to " XWALL_RULE_FILE " success!"
                       : "Save rules to " XWALL_RULE_FILE " fail!";
        data_len = strlen(buff);
        resp     = xwall_response_create(ret ? XWALL_TYPE_OK : XWALL_TYPE_ERROR,
                                     data_len, buff);
        if (!resp) {
            pr_err("[SAVERULE] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_READLOG:
        buff_heap =
            xwall_logtable_read(log_table, ntohl(req->msg.read_log.start_idx),
                                ntohl(req->msg.read_log.end_idx), &data_len);
        if (!buff_heap) {
            pr_err("[READLOG] Log buffer create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        resp = xwall_response_create(XWALL_TYPE_LOG, data_len, buff_heap);
        if (!resp) {
            pr_err("[READLOG] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_CLRLOG:
        xwall_logtable_clear(log_table);
        buff     = "Clear log table success!";
        data_len = strlen(buff);
        resp     = xwall_response_create(XWALL_TYPE_OK, data_len, buff);
        if (!resp) {
            pr_err("[CLRLOG] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_READMLOG:
        buff_heap = xwall_mlogtable_read(
            mlog_table, ntohl(req->msg.read_mlog.start_idx),
            ntohl(req->msg.read_mlog.end_idx), &data_len);
        if (!buff_heap) {
            pr_err("[READNLOG] Manage log buffer create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        resp = xwall_response_create(XWALL_TYPE_MLOG, data_len, buff_heap);
        if (!resp) {
            pr_err("[READMLOG] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_CLRMLOG:
        xwall_mlogtable_clear(mlog_table);
        buff     = "Clear manage log table success!";
        data_len = strlen(buff);
        resp     = xwall_response_create(XWALL_TYPE_OK, data_len, buff);
        if (!resp) {
            pr_err("[CLRMLOG] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_READCONN:
        buff_heap = xwall_hashtable_read(conn_table, &data_len);
        if (!buff_heap) {
            pr_err("[READCONN] Log buffer create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        resp = xwall_response_create(XWALL_TYPE_CONN, data_len, buff_heap);
        if (!resp) {
            pr_err("[READCONN] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_DEFACT:
        default_action = (unsigned int)ntohl(req->msg.def_act);
        if (default_action == NF_DROP)
            xwall_hashtable_clear(conn_table);
        buff     = "Change default action success!";
        data_len = strlen(buff);
        resp     = xwall_response_create(XWALL_TYPE_OK, data_len, buff);
        if (!resp) {
            pr_err("[DEFACT] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    case XWALL_OP_READDEFACT:
        __be32 tmp = htonl(default_action);
        buff       = (char *)&tmp;
        data_len   = sizeof(default_action);
        resp       = xwall_response_create(XWALL_TYPE_OK, data_len, buff);
        if (!resp) {
            pr_err("[READDEFACT] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    default:
        buff     = "Invalid opcode!";
        data_len = strlen(buff);
        resp     = xwall_response_create(XWALL_TYPE_ERROR, data_len, buff);
        if (!resp) {
            pr_err("[DEFAULT] Response create failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        ret = xwall_netlink_send(pid, (char *)resp, sizeof(*resp) + data_len);
        break;
    }

out:
    if (buff_heap)
        kfree(buff_heap);
    if (resp)
        kfree(resp);
    return ret;
}

void xwall_netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    char *data;
    int pid, len;

    nlh = nlmsg_hdr(skb);
    if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
        pr_err("Illegal netlink packet!\n");
        return;
    }

    data = (char *)NLMSG_DATA(nlh);
    pid  = nlh->nlmsg_pid;
    len  = nlh->nlmsg_len - NLMSG_SPACE(0);
    XWALL_PR_INFO("Data recv from user %d.\n", pid);
    xwall_msg_hdr(pid, data, len);
}

/* NETFILTER */
/* PRE ROUTING hook: Destination network address translation. */
unsigned int xwall_nat_in(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state)
{
    // return NF_ACCEPT;
    struct iphdr *iph = ip_hdr(skb);

    if (iph->daddr != xwall_ip_wan)
        return NF_ACCEPT;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + iph->ihl * 4);
        if (nat_table[tcph->dest].valid) {
            if (!ktime_cur_before(nat_table[tcph->dest].timeout)) {
                nat_table[tcph->dest].valid = false;
                return NF_ACCEPT;
            }
            /* Change dst IP to xwall's WAL IP and src port to WAN NAT port. */
            XWALL_PR_INFO(
                "DNAT-TCP: (%pI4,%d > %pI4,%d) => (%pI4,%d > %pI4,%d)",
                &iph->saddr, ntohs(tcph->source), &iph->daddr,
                ntohs(tcph->dest), &iph->saddr, ntohs(tcph->source),
                &nat_table[tcph->dest].lan_addr,
                ntohs(nat_table[tcph->dest].lan_port));
            iph->daddr = nat_table[tcph->dest].lan_addr;
            tcph->dest = nat_table[tcph->dest].lan_port;
            /* Update checksum. */
            xwall_update_checksum_ip(iph);
            xwall_update_checksum_tcp(skb, tcph, iph);
        }
        break;
    case IPPROTO_UDP:
        struct udphdr *udph = (struct udphdr *)((char *)iph + iph->ihl * 4);
        if (nat_table[udph->dest].valid) {
            if (!ktime_cur_before(nat_table[udph->dest].timeout)) {
                nat_table[udph->dest].valid = false;
                return NF_ACCEPT;
            }
            /* Change dst IP to xwall's WAL IP and src port to WAN NAT port. */
            XWALL_PR_INFO(
                "DNAT-UDP: (%pI4,%d > %pI4,%d) => (%pI4,%d > %pI4,%d)",
                &iph->saddr, ntohs(udph->source), &iph->daddr,
                ntohs(udph->dest), &iph->saddr, ntohs(udph->source),
                &nat_table[udph->dest].lan_addr,
                ntohs(nat_table[udph->dest].lan_port));
            iph->daddr = nat_table[udph->dest].lan_addr;
            udph->dest = nat_table[udph->dest].lan_port;
            /* Update checksum. */
            xwall_update_checksum_ip(iph);
            xwall_update_checksum_udp(skb, udph, iph);
        }
        break;
    case IPPROTO_ICMP:
        struct icmphdr *icmph = (struct icmphdr *)((char *)iph + iph->ihl * 4);
        if (nat_table[htons(XWALL_LAN_PORT_ICMP)].valid) {
            if (!ktime_cur_before(
                    nat_table[htons(XWALL_LAN_PORT_ICMP)].timeout)) {
                nat_table[htons(XWALL_LAN_PORT_ICMP)].valid = false;
                return NF_ACCEPT;
            }
            /* Change dst IP to xwall's WAL IP. */
            XWALL_PR_INFO("DNAT-ICMP: (%pI4 > %pI4) => (%pI4 > %pI4)",
                          &iph->saddr, &iph->daddr, &iph->saddr,
                          &nat_table[htons(XWALL_LAN_PORT_ICMP)].lan_addr);
            iph->daddr = nat_table[htons(XWALL_LAN_PORT_ICMP)].lan_addr;
            /* Update checksum. */
            xwall_update_checksum_ip(iph);
            xwall_update_checksum_icmp(skb, icmph, iph);
        }
        break;
    default:
        break;
    }
    return NF_ACCEPT;
}

/* POST ROUTING hook: Source network address translation. */
unsigned int xwall_nat_out(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    __be16 port_wan;

    if ((iph->saddr & ip_lan_mask) != (xwall_ip_lan & ip_lan_mask))
        return NF_ACCEPT;

    if ((iph->daddr & ip_wan_mask) != (xwall_ip_wan & ip_wan_mask))
        return NF_ACCEPT;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + iph->ihl * 4);
        /* Choose a WAN port. */
        port_wan = xwall_nattable_match(iph->saddr, tcph->source);
        if (!port_wan) {
            /* NAT entry doesn't exist, make a new NAT entry. */
            port_wan = htons(nat_port++);
            if (nat_port == 0)
                nat_port = XWALL_NAT_PORT_START;
            nat_table[port_wan].valid    = true;
            nat_table[port_wan].lan_addr = iph->saddr;
            nat_table[port_wan].lan_port = tcph->source;
            nat_table[port_wan].timeout =
                ktime_add_sec(ktime_get_real(), nat_timeout_sec);
        }
        /* Change src IP to xwall's WAL IP and src port to WAN NAT port. */
        XWALL_PR_INFO("SNAT-TCP: (%pI4,%d > %pI4,%d) => (%pI4,%d > %pI4,%d)",
                      &iph->saddr, ntohs(tcph->source), &iph->daddr,
                      ntohs(tcph->dest), &xwall_ip_wan, ntohs(port_wan),
                      &iph->daddr, ntohs(tcph->dest));
        iph->saddr   = xwall_ip_wan;
        tcph->source = port_wan;
        /* Update checksum. */
        xwall_update_checksum_ip(iph);
        xwall_update_checksum_tcp(skb, tcph, iph);
        break;
    case IPPROTO_UDP:
        struct udphdr *udph = (struct udphdr *)((char *)iph + iph->ihl * 4);
        /* Choose a WAN port. */
        port_wan = xwall_nattable_match(iph->saddr, udph->source);
        if (!port_wan) {
            /* NAT entry doesn't exist, make a new NAT entry. */
            port_wan = htons(nat_port++);
            if (nat_port == 0)
                nat_port = XWALL_NAT_PORT_START;
            nat_table[port_wan].valid    = true;
            nat_table[port_wan].lan_addr = iph->saddr;
            nat_table[port_wan].lan_port = udph->source;
            nat_table[port_wan].timeout =
                ktime_add_sec(ktime_get_real(), nat_timeout_sec);
        }
        /* Change src IP to xwall's WAL IP and src port to WAN NAT port. */
        XWALL_PR_INFO("SNAT-UDP: (%pI4,%d > %pI4,%d) => (%pI4,%d > %pI4,%d)",
                      &iph->saddr, ntohs(udph->source), &iph->daddr,
                      ntohs(udph->dest), &xwall_ip_wan, ntohs(port_wan),
                      &iph->daddr, ntohs(udph->dest));
        iph->saddr   = xwall_ip_wan;
        udph->source = port_wan;
        /* Update checksum. */
        xwall_update_checksum_ip(iph);
        xwall_update_checksum_udp(skb, udph, iph);
        break;
    case IPPROTO_ICMP:
        struct icmphdr *icmph = (struct icmphdr *)((char *)iph + iph->ihl * 4);
        // /* Choose a WAN port. */
        // port_wan = xwall_nattable_match(iph->saddr, XWALL_LAN_PORT_ICMP);
        // if (!port_wan) {
        //     /* NAT entry doesn't exist, make a new NAT entry. */
        //     port_wan = htons(nat_port++);
        //     if (nat_port == 0)
        //         nat_port = XWALL_NAT_PORT_START;
        //     nat_table[port_wan].valid    = true;
        //     nat_table[port_wan].lan_addr = iph->saddr;
        //     nat_table[port_wan].lan_port = XWALL_LAN_PORT_ICMP;
        //     nat_table[port_wan].timeout =
        //         ktime_add_sec(ktime_get_real(), nat_timeout_sec);
        // }
        port_wan                     = htons(XWALL_LAN_PORT_ICMP);
        nat_table[port_wan].valid    = true;
        nat_table[port_wan].lan_addr = iph->saddr;
        nat_table[port_wan].lan_port = XWALL_LAN_PORT_ICMP;
        nat_table[port_wan].timeout =
            ktime_add_sec(ktime_get_real(), nat_timeout_sec);
        /* Change src IP to xwall's WAL IP. */
        XWALL_PR_INFO("SNAT-ICMP: (%pI4 > %pI4) => (%pI4 > %pI4)", &iph->saddr,
                      &iph->daddr, &xwall_ip_wan, &iph->daddr);
        iph->saddr = xwall_ip_wan;
        /* Update checksum. */
        xwall_update_checksum_ip(iph);
        xwall_update_checksum_icmp(skb, icmph, iph);
        break;
    default:
        /* TODO. */
        break;
    }

    return NF_ACCEPT;
}

unsigned int xwall_filter(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state)
{
    // TODO: catch the TCP state accurately.

    /* Step 1: init connection information. */
    bool new_conn                 = false;
    unsigned int res              = default_action;
    struct iphdr *iph             = ip_hdr(skb);
    struct xwall_index *idx       = xwall_index_create(iph);
    struct xwall_connection *conn = xwall_connection_create(iph);
    struct xwall_rule *rule       = NULL;
    struct xwall_log *log         = NULL;
    xwall_show_packet(iph);

    /* Step 2: find current connection in connection table. */
    if (xwall_hashtable_match(conn_table, conn, idx)) {
        XWALL_PR_INFO("    Connection existed, accept.\n");
        res = NF_ACCEPT;
        if (default_logging) {
            log = xwall_log_create(skb, NF_ACCEPT);
            xwall_logtable_add(log_table, log);
        }
        goto out;
    }

    /* Step 3: if TCP, must be SYN to continue to match rules. */
    if (iph->protocol == IPPROTO_TCP && !IS_SYN((void *)iph + iph->ihl * 4)) {
        XWALL_PR_INFO("    No such TCP connection and not SYN, drop.");
        res = NF_DROP;
        if (default_logging) {
            log = xwall_log_create(skb, NF_DROP);
            xwall_logtable_add(log_table, log);
        }
        goto out;
    }

    /* Step 4: if ICMP, must be Echo request to continue to match rules. */
    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)((char *)iph + iph->ihl * 4);
        if (!IS_ECHO_REQUEST(icmph)) {
            XWALL_PR_INFO(
                "    No such ICMP connection and not ECHO REQUEST, drop.");
            res = NF_DROP;
            if (default_logging) {
                log = xwall_log_create(skb, NF_DROP);
                xwall_logtable_add(log_table, log);
            }
            goto out;
        }
    }

    /* Step 5: find current connection in rule table. */
    rule = xwall_ruletable_match(rule_table, conn);
    if (rule) {
        res = ntohl(rule->action);
        if (rule->logging) {
            log = xwall_log_create(skb, ntohl(rule->action));
            xwall_logtable_add(log_table, log);
        }
        XWALL_PR_INFO("    Match rule, use rule action.\n");
        if (res == NF_ACCEPT) {
            new_conn = true;
            xwall_hashtable_add(conn_table, conn, idx);
            XWALL_PR_INFO("    Rule action is accept, add new connection.\n");
        }
    } else {
        res = default_action;
        if (default_logging) {
            log = xwall_log_create(skb, default_action);
            xwall_logtable_add(log_table, log);
        }
        XWALL_PR_INFO("    No matching rule, use default action.\n");
        if (res == NF_ACCEPT) {
            new_conn = true;
            xwall_hashtable_add(conn_table, conn, idx);
            XWALL_PR_INFO(
                "    Default action is accept, add new connection.\n");
        }
    }

out:
    if (!new_conn)
        kfree(conn);
    kfree(idx);
    return res;
}

void xwall_add_default_rule(void)
{
    struct xwall_rule *def_rule = NULL;

    def_rule            = kvzalloc(sizeof(*def_rule), GFP_KERNEL);
    def_rule->saddr     = 192 + (168 << 8) + (33 << 16) + (0 << 24);
    def_rule->daddr     = 192 + (168 << 8) + (33 << 16) + (0 << 24);
    def_rule->smask     = 0x00ffffff;
    def_rule->dmask     = 0x00ffffff;
    def_rule->sport_min = 0;
    def_rule->sport_max = 0xffff;
    def_rule->dport_min = 0;
    def_rule->dport_max = 0xffff;
    def_rule->protocol  = IPPROTO_TCP;
    def_rule->action    = htonl(NF_ACCEPT);
    def_rule->logging   = true;
    def_rule->timeout   = htonll(ktime_add_sec(ktime_get_real(), 3600 * 24));
    xwall_ruletable_add(rule_table, def_rule);

    // def_rule            = kvzalloc(sizeof(*def_rule), GFP_KERNEL);
    // def_rule->saddr     = 127 + (0 << 8) + (0 << 16) + (0 << 24);
    // def_rule->daddr     = 127 + (0 << 8) + (0 << 16) + (0 << 24);
    // def_rule->smask     = 0x00ffffff;
    // def_rule->dmask     = 0x00ffffff;
    // def_rule->sport_min = 0;
    // def_rule->sport_max = 0xffff;
    // def_rule->dport_min = 0;
    // def_rule->dport_max = 0xffff;
    // def_rule->protocol  = IPPROTO_TCP;
    // def_rule->action    = htonl(NF_ACCEPT);
    // def_rule->logging   = true;
    // def_rule->timeout   = htonll(ktime_add_sec(ktime_get_real(), 3600 * 24));
    // xwall_ruletable_add(rule_table, def_rule);

    def_rule            = kvzalloc(sizeof(*def_rule), GFP_KERNEL);
    def_rule->saddr     = 192 + (168 << 8) + (44 << 16) + (0 << 24);
    def_rule->daddr     = 10 + (0 << 8) + (12 << 16) + (0 << 24);
    def_rule->smask     = 0x00ffffff;
    def_rule->dmask     = 0x00ffffff;
    def_rule->sport_min = 0;
    def_rule->sport_max = 0xffff;
    def_rule->dport_min = 0;
    def_rule->dport_max = 0xffff;
    def_rule->protocol  = IPPROTO_ICMP;
    def_rule->action    = htonl(NF_ACCEPT);
    def_rule->logging   = true;
    def_rule->timeout   = htonll(ktime_add_sec(ktime_get_real(), 3600 * 24));
    xwall_ruletable_add(rule_table, def_rule);

    def_rule            = kvzalloc(sizeof(*def_rule), GFP_KERNEL);
    def_rule->saddr     = 192 + (168 << 8) + (44 << 16) + (0 << 24);
    def_rule->daddr     = 10 + (0 << 8) + (12 << 16) + (0 << 24);
    def_rule->smask     = 0x00ffffff;
    def_rule->dmask     = 0x00ffffff;
    def_rule->sport_min = 0;
    def_rule->sport_max = 0xffff;
    def_rule->dport_min = 0;
    def_rule->dport_max = 0xffff;
    def_rule->protocol  = IPPROTO_TCP;
    def_rule->action    = htonl(NF_ACCEPT);
    def_rule->logging   = true;
    def_rule->timeout   = htonll(ktime_add_sec(ktime_get_real(), 3600 * 24));
    xwall_ruletable_add(rule_table, def_rule);

    def_rule            = kvzalloc(sizeof(*def_rule), GFP_KERNEL);
    def_rule->saddr     = 192 + (168 << 8) + (44 << 16) + (0 << 24);
    def_rule->daddr     = 10 + (0 << 8) + (12 << 16) + (0 << 24);
    def_rule->smask     = 0x00ffffff;
    def_rule->dmask     = 0x00ffffff;
    def_rule->sport_min = 0;
    def_rule->sport_max = 0xffff;
    def_rule->dport_min = 0;
    def_rule->dport_max = 0xffff;
    def_rule->protocol  = IPPROTO_UDP;
    def_rule->action    = htonl(NF_ACCEPT);
    def_rule->logging   = true;
    def_rule->timeout   = htonll(ktime_add_sec(ktime_get_real(), 3600 * 24));
    xwall_ruletable_add(rule_table, def_rule);
}

static int __init xwall_init(void)
{
    int err;
    struct xwall_mlog *mlog;
    struct netlink_kernel_cfg nl_cfg = {
        .input = xwall_netlink_recv,
    };

    // XWALL_PR_INFO("size of struct xwall_conn: %ld", sizeof(struct
    // xwall_conn)); XWALL_PR_INFO("size of unsigned long: %ld", sizeof(unsigned
    // long)); XWALL_PR_INFO("time stamp: %lld", ktime_get_real());
    // XWALL_PR_INFO("size of rule: %ld", sizeof(struct xwall_rule));

    mlog_table = xwall_mlogtable_create();
    if (!mlog_table) {
        pr_err("Manage log table create failed.\n");
        err = -ENOMEM;
        goto err_out;
    }

    log_table = xwall_logtable_create();
    if (!log_table) {
        pr_err("Log table create failed.\n");
        err = -ENOMEM;
        goto err_free_manage_logtable;
    }

    conn_table = xwall_hashtable_create();
    if (!conn_table) {
        pr_err("Connection hashtable create failed.\n");
        err = -ENOMEM;
        goto err_free_logtable;
    }

    rule_table = xwall_ruletable_create();
    if (!rule_table) {
        pr_err("Rule table create failed.\n");
        err = -ENOMEM;
        goto err_free_hashtable;
    }

    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &nl_cfg);
    if (!nl_sk) {
        pr_err("Netlink kernel create socket failed.\n");
        err = -ENOMEM;
        goto err_free_ruletable;
    }

    err = nf_register_net_hooks(&init_net, nf_xwall_ops,
                                ARRAY_SIZE(nf_xwall_ops));
    if (err != 0) {
        pr_err("Netfilter register net hooks failed.\n");
        goto err_release_sock;
    }

    XWALL_PR_INFO("XWALL module loaded.");

    mlog = xwall_mlog_create();
    sprintf(mlog->msg, "XWALL module loaded.");
    xwall_mlogtable_add(mlog_table, mlog);

    err = xwall_load_rule(rule_table);
    if (err == false) {
        xwall_add_default_rule();
        XWALL_PR_INFO("XWALL default rule added.");
    }

    timer_setup(&conn_timer, xwall_timer_callback, 0);
    conn_timer.expires = jiffies + XWALL_CLEAN_CONN_INVERVAL_SEC * HZ;
    add_timer(&conn_timer);

    return 0;

err_release_sock:
    sock_release(nl_sk->sk_socket);
err_free_ruletable:
    xwall_ruletable_clear(rule_table);
    kfree(rule_table);
err_free_hashtable:
    xwall_hashtable_clear(conn_table);
    kfree(conn_table);
err_free_logtable:
    xwall_logtable_clear(log_table);
    kfree(log_table);
err_free_manage_logtable:
    xwall_mlogtable_clear(mlog_table);
    kfree(mlog_table);
err_out:
    return err;
}

static void __exit xwall_exit(void)
{
    nf_unregister_net_hooks(&init_net, nf_xwall_ops, ARRAY_SIZE(nf_xwall_ops));
    sock_release(nl_sk->sk_socket);
    del_timer(&conn_timer);
    xwall_hashtable_clear(conn_table);
    kfree(conn_table);
    xwall_ruletable_clear(rule_table);
    kfree(rule_table);
    xwall_logtable_clear(log_table);
    kfree(log_table);
    xwall_mlogtable_clear(mlog_table);
    kfree(mlog_table);

    XWALL_PR_INFO("XWALL module exited.\n");
}

module_init(xwall_init);
module_exit(xwall_exit);

MODULE_AUTHOR("Xu Biang <xubiang@foxmail.com>");
MODULE_DESCRIPTION("A Simple Firewall - XWALL");
MODULE_LICENSE("GPL");
