#include "cJSON.h"
#include <arpa/inet.h>
#include <assert.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#define MSG_LEN 25600

struct list_head {
    struct list_head *next, *prev;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

#include "../module/xwall_public.h"

struct user2kernel {
    struct nlmsghdr hdr;
    struct xwall_request req;
};

struct kernel2user {
    struct nlmsghdr hdr;
    struct xwall_response resp;
    char msg[MSG_LEN];
};

int sk_nl;
struct sockaddr_nl skad_nl_user, skad_nl_kernel;

char *to_upper(char *str)
{
    assert(str != NULL);
    for (char *i = str; *i != '\0'; ++i) {
        if (*i >= 'a' && *i <= 'z')
            *i -= 'a' - 'A';
    }
    return str;
}

void init_netlink()
{
    sk_nl = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if (sk_nl < 0) {
        fprintf(stderr, "Can not create a netlink socket, please check whether"
                        " the kernel module <xwall.ko> is installed.\n");
        exit(-1);
    }

    memset(&skad_nl_user, 0, sizeof(skad_nl_user));
    skad_nl_user.nl_family = AF_NETLINK;
    skad_nl_user.nl_pid    = getpid();
    skad_nl_user.nl_groups = 0;
    if (bind(sk_nl, (struct sockaddr *)&skad_nl_user, sizeof(skad_nl_user))) {
        perror("bind");
        exit(-1);
    }

    memset(&skad_nl_kernel, 0, sizeof(skad_nl_kernel));
    skad_nl_kernel.nl_family = AF_NETLINK;
    skad_nl_kernel.nl_pid    = 0;
    skad_nl_kernel.nl_groups = 0;
}

__u8 get_protocol_from_str(char *protocol)
{
    // TODO: more protocol
    if (strcmp(to_upper(protocol), "TCP") == 0) {
        return IPPROTO_TCP;
    } else if (strcmp(to_upper(protocol), "UDP") == 0) {
        return IPPROTO_UDP;
    } else if (strcmp(to_upper(protocol), "ICMP") == 0) {
        return IPPROTO_ICMP;
    } else {
        fprintf(stderr, "Invalid protocol %s, should be TCP/UDP/ICMP.\n",
                protocol);
        exit(-1);
    }
}

unsigned int get_action_from_str(char *action)
{
    if (strcmp(to_upper(action), "ACCEPT") == 0) {
        return NF_ACCEPT;
    } else if (strcmp(to_upper(action), "DROP") == 0) {
        return NF_DROP;
    } else {
        fprintf(stderr, "Invalid action %s, should be ACCEPT/DROP.\n", action);
        exit(-1);
    }
}

__u8 get_logging_from_str(char *logging)
{
    if (strcmp(to_upper(logging), "TRUE") == 0) {
        return true;
    } else if (strcmp(to_upper(logging), "FALSE") == 0) {
        return false;
    } else {
        fprintf(stderr, "Invalid logging %s, should be TRUE/FALSE.\n", logging);
        exit(-1);
    }
}

char *get_protocol_from_id(const __u8 protocol)
{
    if (protocol == IPPROTO_TCP) {
        return "TCP";
    } else if (protocol == IPPROTO_UDP) {
        return "UDP";
    } else if (protocol == IPPROTO_ICMP) {
        return "ICMP";
    } else {
        return "OTHERS";
    }
}

char *get_action_from_id(const unsigned int action)
{
    if (action == NF_ACCEPT) {
        return "ACCEPT";
    } else if (action == NF_DROP) {
        return "DROP";
    } else {
        return "OTHERS";
    }
}

char *get_logging_from_id(const __u8 logging)
{
    if (logging == true) {
        return "TRUE";
    } else if (logging == false) {
        return "FALSE";
    } else {
        return "OTHERS";
    }
}

struct user2kernel *xwall_user2kernel_create()
{
    struct user2kernel *user2kernel =
        (struct user2kernel *)malloc(sizeof(*user2kernel));
    if (user2kernel == NULL) {
        perror("user2kernel malloc");
        exit(-1);
    }
    memset(user2kernel, '\0', sizeof(struct user2kernel));

    user2kernel->hdr.nlmsg_len   = NLMSG_SPACE(sizeof(struct xwall_request));
    user2kernel->hdr.nlmsg_flags = 0;
    user2kernel->hdr.nlmsg_type  = 0;
    user2kernel->hdr.nlmsg_seq   = 0;
    user2kernel->hdr.nlmsg_pid   = skad_nl_user.nl_pid;

    return user2kernel;
}

ssize_t xwall_user2kernel_send(struct user2kernel *user2kernel)
{
    ssize_t ret;

    // printf("message sendto kernel with length %d.\n",
    //        user2kernel->hdr.nlmsg_len);
    ret = sendto(sk_nl, user2kernel, user2kernel->hdr.nlmsg_len, 0,
                 (struct sockaddr *)&skad_nl_kernel, sizeof(skad_nl_kernel));
    if (!ret) {
        perror("sendto");
        exit(-1);
    }

    return ret;
}

ssize_t xwall_kernel2user_recv(struct kernel2user *kernel2user)
{
    ssize_t ret;
    int len = sizeof(struct sockaddr_nl);

    ret = recvfrom(sk_nl, kernel2user, sizeof(*kernel2user), 0,
                   (struct sockaddr *)&skad_nl_kernel, &len);
    if (!ret) {
        perror("recvfrom");
        exit(-1);
    }
    // printf("message recvfrom kernel with length %ld.\n", ret);

    return ret;
}

void xwall_add_rule(struct xwall_rule *rule)
{
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();

    user2kernel->req.opcode       = XWALL_OP_ADDRULE;
    user2kernel->req.msg.rule_add = *rule;
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_OK) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    printf("%s\n", kernel2user.msg);
}

void xwall_del_rule(unsigned int del_idx)
{
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();

    user2kernel->req.opcode           = XWALL_OP_DELRULE;
    user2kernel->req.msg.rule_del_idx = htonl(del_idx);
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_OK &&
        kernel2user.resp.type != XWALL_TYPE_ERROR) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    if (kernel2user.resp.type == XWALL_TYPE_ERROR) {
        fprintf(stderr, "%s\n", kernel2user.msg);
    } else {
        printf("%s\n", kernel2user.msg);
    }
}

void xwall_read_rule(unsigned int start_idx, unsigned int end_idx, bool json)
{
    int i;
    time_t ts;
    char timeout_str[128];
    unsigned int rule_num = 0;
    struct in_addr addr;
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();
    struct xwall_rule *rule = NULL, zero_rule = {0};

    user2kernel->req.opcode                  = XWALL_OP_READRULE;
    user2kernel->req.msg.read_rule.start_idx = htonl(start_idx);
    user2kernel->req.msg.read_rule.end_idx   = htonl(end_idx);
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_RULE) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    rule_num = ntohl(*(uint32_t *)kernel2user.msg);
    rule = (struct xwall_rule *)((char *)kernel2user.msg + sizeof(uint32_t));
    if (!json) {
        printf("rule num: %d\n", rule_num);
        for (i = start_idx; i < end_idx; i++, rule++) {
            if (memcmp(rule, &zero_rule, sizeof(*rule)) == 0)
                continue;
            printf("[rule %d]\n", ntohl(rule->idx));
            memcpy(&addr, &rule->saddr, sizeof(addr));
            printf("saddr    : %s\n", inet_ntoa(addr));
            memcpy(&addr, &rule->daddr, sizeof(addr));
            printf("daddr    : %s\n", inet_ntoa(addr));
            memcpy(&addr, &rule->smask, sizeof(addr));
            printf("smask    : %s\n", inet_ntoa(addr));
            memcpy(&addr, &rule->dmask, sizeof(addr));
            printf("dmask    : %s\n", inet_ntoa(addr));
            printf("sport    : %d ~ %d\n", ntohs(rule->sport_min),
                   ntohs(rule->sport_max));
            printf("dport    : %d ~ %d\n", ntohs(rule->dport_min),
                   ntohs(rule->dport_max));
            printf("protocol : %s\n", get_protocol_from_id(rule->protocol));
            printf("action   : %s\n", get_action_from_id(ntohl(rule->action)));
            printf("logging  : %s\n", get_logging_from_id(rule->logging));
            ts = ntohll(rule->timeout) / 1000000000L;
            strftime(timeout_str, 128, "%F %T", localtime(&ts));
            printf("timeout  : %s\n", timeout_str);
        }
    } else {
        char *string   = NULL;
        cJSON *monitor = cJSON_CreateObject();
        if (!cJSON_AddNumberToObject(monitor, "rule_num", rule_num))
            goto end;
        cJSON *rules_json = cJSON_AddArrayToObject(monitor, "rules");
        for (i = start_idx; i < end_idx; i++, rule++) {
            if (memcmp(rule, &zero_rule, sizeof(*rule)) == 0)
                continue;
            cJSON *rule_json = cJSON_CreateObject();

            ts = ntohll(rule->timeout) / 1000000000L;
            strftime(timeout_str, 128, "%F %T", localtime(&ts));

            if (!cJSON_AddNumberToObject(rule_json, "idx", ntohl(rule->idx)))
                goto end;
            memcpy(&addr, &rule->saddr, sizeof(addr));
            if (!cJSON_AddStringToObject(rule_json, "saddr", inet_ntoa(addr)))
                goto end;
            memcpy(&addr, &rule->daddr, sizeof(addr));
            if (!cJSON_AddStringToObject(rule_json, "daddr", inet_ntoa(addr)))
                goto end;
            memcpy(&addr, &rule->smask, sizeof(addr));
            if (!cJSON_AddStringToObject(rule_json, "smask", inet_ntoa(addr)))
                goto end;
            memcpy(&addr, &rule->dmask, sizeof(addr));
            if (!cJSON_AddStringToObject(rule_json, "dmask", inet_ntoa(addr)))
                goto end;
            if (!cJSON_AddNumberToObject(rule_json, "sport_min",
                                         ntohs(rule->sport_min)))
                goto end;
            if (!cJSON_AddNumberToObject(rule_json, "sport_max",
                                         ntohs(rule->sport_max)))
                goto end;
            if (!cJSON_AddNumberToObject(rule_json, "dport_min",
                                         ntohs(rule->dport_min)))
                goto end;
            if (!cJSON_AddNumberToObject(rule_json, "dport_max",
                                         ntohs(rule->dport_max)))
                goto end;
            if (!cJSON_AddStringToObject(rule_json, "protocol",
                                         get_protocol_from_id(rule->protocol)))
                goto end;
            if (!cJSON_AddStringToObject(
                    rule_json, "action",
                    get_action_from_id(ntohl(rule->action))))
                goto end;
            if (!cJSON_AddStringToObject(rule_json, "logging",
                                         get_logging_from_id(rule->logging)))
                goto end;
            if (!cJSON_AddStringToObject(rule_json, "timeout", timeout_str))
                goto end;
            cJSON_AddItemToArray(rules_json, rule_json);
        }
        string = cJSON_Print(monitor);
        printf("%s\n", string);
    end:
        cJSON_Delete(monitor);
    }
}

void xwall_save_rule()
{
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();

    user2kernel->req.opcode = XWALL_OP_SAVERULE;
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_OK &&
        kernel2user.resp.type != XWALL_TYPE_ERROR) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    if (kernel2user.resp.type == XWALL_TYPE_ERROR) {
        fprintf(stderr, "%s\n", kernel2user.msg);
    } else {
        printf("%s\n", kernel2user.msg);
    }
}

void xwall_read_log(unsigned int start_idx, unsigned int end_idx, bool json)
{
    int i;
    time_t ts;
    char timeout_str[128];
    unsigned int log_num = 0;
    struct in_addr addr;
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();
    struct xwall_log *log = NULL, zero_log = {0};

    user2kernel->req.opcode                 = XWALL_OP_READLOG;
    user2kernel->req.msg.read_log.start_idx = htonl(start_idx);
    user2kernel->req.msg.read_log.end_idx   = htonl(end_idx);
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_LOG) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    log_num = ntohl(*(uint32_t *)kernel2user.msg);
    log     = (struct xwall_log *)((char *)kernel2user.msg + sizeof(uint32_t));
    if (!json) {
        printf("log num: %d\n", log_num);
        for (i = start_idx; i < end_idx; i++, log++) {
            if (memcmp(log, &zero_log, sizeof(*log)) == 0)
                continue;
            printf("[log %d]\n", ntohl(log->idx));
            ts = ntohll(log->ts) / 1000000000L;
            strftime(timeout_str, 128, "%F %T", localtime(&ts));
            printf("ts       : %s\n", timeout_str);
            memcpy(&addr, &log->saddr, sizeof(addr));
            printf("saddr    : %s\n", inet_ntoa(addr));
            memcpy(&addr, &log->daddr, sizeof(addr));
            printf("daddr    : %s\n", inet_ntoa(addr));
            printf("protocol : %s\n", get_protocol_from_id(log->protocol));
            if (log->protocol == IPPROTO_TCP) {
                printf("sport    : %d\n", ntohs(log->tcp.sport));
                printf("dport    : %d\n", ntohs(log->tcp.dport));
            } else if (log->protocol == IPPROTO_UDP) {
                printf("sport    : %d\n", ntohs(log->udp.sport));
                printf("dport    : %d\n", ntohs(log->udp.dport));
            } else if (log->protocol == IPPROTO_ICMP) {
                printf("type     : %d\n", log->icmp.type);
                printf("code     : %d\n", log->icmp.code);
            }
            printf("len      : %d\n", ntohs(log->len));
            printf("action   : %s\n", get_action_from_id(ntohl(log->action)));
        }
    } else {
        char *string   = NULL;
        cJSON *monitor = cJSON_CreateObject();
        if (!cJSON_AddNumberToObject(monitor, "log_num", log_num))
            goto end;
        cJSON *logs_json = cJSON_AddArrayToObject(monitor, "logs");
        for (i = start_idx; i < end_idx; i++, log++) {
            if (memcmp(log, &zero_log, sizeof(*log)) == 0)
                continue;
            cJSON *log_json = cJSON_CreateObject();

            ts = ntohll(log->ts) / 1000000000L;
            strftime(timeout_str, 128, "%F %T", localtime(&ts));

            if (!cJSON_AddNumberToObject(log_json, "idx", ntohl(log->idx)))
                goto end;
            if (!cJSON_AddStringToObject(log_json, "ts", timeout_str))
                goto end;
            memcpy(&addr, &log->saddr, sizeof(addr));
            if (!cJSON_AddStringToObject(log_json, "saddr", inet_ntoa(addr)))
                goto end;
            memcpy(&addr, &log->daddr, sizeof(addr));
            if (!cJSON_AddStringToObject(log_json, "daddr", inet_ntoa(addr)))
                goto end;
            if (!cJSON_AddStringToObject(log_json, "protocol",
                                         get_protocol_from_id(log->protocol)))
                goto end;
            if (log->protocol == IPPROTO_UDP) {
                if (!cJSON_AddNumberToObject(log_json, "sport",
                                             ntohs(log->udp.sport)))
                    goto end;
                if (!cJSON_AddNumberToObject(log_json, "dport",
                                             ntohs(log->udp.dport)))
                    goto end;
            } else if (log->protocol == IPPROTO_TCP) {
                if (!cJSON_AddNumberToObject(log_json, "sport",
                                             ntohs(log->tcp.sport)))
                    goto end;
                if (!cJSON_AddNumberToObject(log_json, "dport",
                                             ntohs(log->tcp.dport)))
                    goto end;
            } else if (log->protocol == IPPROTO_ICMP) {
                if (!cJSON_AddNumberToObject(log_json, "type", log->icmp.type))
                    goto end;
                if (!cJSON_AddNumberToObject(log_json, "code", log->icmp.code))
                    goto end;
            }
            if (!cJSON_AddNumberToObject(log_json, "len", ntohs(log->len)))
                goto end;
            if (!cJSON_AddStringToObject(
                    log_json, "action", get_action_from_id(ntohl(log->action))))
                goto end;
            cJSON_AddItemToArray(logs_json, log_json);
        }
        string = cJSON_Print(monitor);
        printf("%s\n", string);
    end:
        cJSON_Delete(monitor);
    }
}

void xwall_clear_log()
{
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();

    user2kernel->req.opcode = XWALL_OP_CLRLOG;
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_OK) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    printf("%s\n", kernel2user.msg);
}

void xwall_read_mlog(unsigned int start_idx, unsigned int end_idx, bool json)
{
    int i;
    time_t ts;
    char timeout_str[128];
    unsigned int mlog_num           = 0;
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();
    struct xwall_mlog *mlog = NULL, zero_mlog = {0};

    user2kernel->req.opcode                 = XWALL_OP_READMLOG;
    user2kernel->req.msg.read_log.start_idx = htonl(start_idx);
    user2kernel->req.msg.read_log.end_idx   = htonl(end_idx);
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_MLOG) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    mlog_num = ntohl(*(uint32_t *)kernel2user.msg);
    mlog = (struct xwall_mlog *)((char *)kernel2user.msg + sizeof(uint32_t));
    if (!json) {
        printf("mlog num: %d\n", mlog_num);
        for (i = start_idx; i < end_idx; i++, mlog++) {
            if (memcmp(mlog, &zero_mlog, sizeof(*mlog)) == 0)
                continue;
            printf("[mlog %d]\n", ntohl(mlog->idx));
            ts = ntohll(mlog->ts) / 1000000000L;
            strftime(timeout_str, 128, "%F %T", localtime(&ts));
            printf("ts       : %s\n", timeout_str);
            printf("msg      : %s\n", mlog->msg);
        }
    } else {
        char *string   = NULL;
        cJSON *monitor = cJSON_CreateObject();
        if (!cJSON_AddNumberToObject(monitor, "mlog_num", mlog_num))
            goto end;
        cJSON *mlogs_json = cJSON_AddArrayToObject(monitor, "mlogs");
        for (i = start_idx; i < end_idx; i++, mlog++) {
            if (memcmp(mlog, &zero_mlog, sizeof(*mlog)) == 0)
                continue;
            cJSON *mlog_json = cJSON_CreateObject();

            ts = ntohll(mlog->ts) / 1000000000L;
            strftime(timeout_str, 128, "%F %T", localtime(&ts));

            if (!cJSON_AddNumberToObject(mlog_json, "idx", ntohl(mlog->idx)))
                goto end;
            if (!cJSON_AddStringToObject(mlog_json, "ts", timeout_str))
                goto end;
            if (!cJSON_AddStringToObject(mlog_json, "msg", mlog->msg))
                goto end;
            cJSON_AddItemToArray(mlogs_json, mlog_json);
        }
        string = cJSON_Print(monitor);
        printf("%s\n", string);
    end:
        cJSON_Delete(monitor);
    }
}

void xwall_clear_mlog()
{
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();

    user2kernel->req.opcode = XWALL_OP_CLRMLOG;
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_OK) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    printf("%s\n", kernel2user.msg);
}

void xwall_read_conn(bool json)
{
    int i;
    time_t ts;
    char timeout_str[128];
    unsigned int conn_num = 0;
    struct in_addr addr;
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();
    struct xwall_connection *conn = NULL, zero_conn = {0};

    user2kernel->req.opcode = XWALL_OP_READCONN;
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_CONN) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    conn_num = ntohl(*(uint32_t *)kernel2user.msg);
    conn =
        (struct xwall_connection *)((char *)kernel2user.msg + sizeof(uint32_t));
    if (!json) {
        printf("conn num: %d\n", conn_num);
        for (i = 0; i < conn_num; i++, conn++) {
            if (memcmp(conn, &zero_conn, sizeof(*conn)) == 0)
                continue;
            printf("[conn %d]\n", i);
            memcpy(&addr, &conn->saddr, sizeof(addr));
            printf("saddr    : %s\n", inet_ntoa(addr));
            memcpy(&addr, &conn->daddr, sizeof(addr));
            printf("daddr    : %s\n", inet_ntoa(addr));
            printf("protocol : %s\n", get_protocol_from_id(conn->protocol));
            if (conn->protocol == IPPROTO_TCP) {
                printf("sport    : %d\n", ntohs(conn->tcp.sport));
                printf("dport    : %d\n", ntohs(conn->tcp.dport));
                // printf("state    : %d\n", ntohs(conn->tcp.state));
            } else if (conn->protocol == IPPROTO_UDP) {
                printf("sport    : %d\n", ntohs(conn->udp.sport));
                printf("dport    : %d\n", ntohs(conn->udp.dport));
            } else if (conn->protocol == IPPROTO_ICMP) {
                printf("type     : %d\n", conn->icmp.type);
                printf("code     : %d\n", conn->icmp.code);
            }
            ts = ntohll(conn->timeout) / 1000000000L;
            strftime(timeout_str, 128, "%F %T", localtime(&ts));
            printf("timeout  : %s\n", timeout_str);
        }
    } else {
        char *string   = NULL;
        cJSON *monitor = cJSON_CreateObject();
        if (!cJSON_AddNumberToObject(monitor, "conn_num", conn_num))
            goto end;
        cJSON *conns_json = cJSON_AddArrayToObject(monitor, "conns");
        for (i = 0; i < conn_num; i++, conn++) {
            if (memcmp(conn, &zero_conn, sizeof(*conn)) == 0)
                continue;
            cJSON *conn_json = cJSON_CreateObject();
            if (!cJSON_AddNumberToObject(conn_json, "idx", i))
                goto end;
            memcpy(&addr, &conn->saddr, sizeof(addr));
            if (!cJSON_AddStringToObject(conn_json, "saddr", inet_ntoa(addr)))
                goto end;
            memcpy(&addr, &conn->daddr, sizeof(addr));
            if (!cJSON_AddStringToObject(conn_json, "daddr", inet_ntoa(addr)))
                goto end;
            if (!cJSON_AddStringToObject(conn_json, "protocol",
                                         get_protocol_from_id(conn->protocol)))
                goto end;
            if (conn->protocol == IPPROTO_UDP) {
                if (!cJSON_AddNumberToObject(conn_json, "sport",
                                             ntohs(conn->udp.sport)))
                    goto end;
                if (!cJSON_AddNumberToObject(conn_json, "dport",
                                             ntohs(conn->udp.dport)))
                    goto end;
            } else if (conn->protocol == IPPROTO_TCP) {
                if (!cJSON_AddNumberToObject(conn_json, "sport",
                                             ntohs(conn->tcp.sport)))
                    goto end;
                if (!cJSON_AddNumberToObject(conn_json, "dport",
                                             ntohs(conn->tcp.dport)))
                    goto end;
            } else if (conn->protocol == IPPROTO_ICMP) {
                if (!cJSON_AddNumberToObject(conn_json, "type",
                                             conn->icmp.type))
                    goto end;
                if (!cJSON_AddNumberToObject(conn_json, "code",
                                             conn->icmp.code))
                    goto end;
            }
            ts = ntohll(conn->timeout) / 1000000000L;
            strftime(timeout_str, 128, "%F %T", localtime(&ts));
            if (!cJSON_AddStringToObject(conn_json, "timeout", timeout_str))
                goto end;
            cJSON_AddItemToArray(conns_json, conn_json);
        }
        string = cJSON_Print(monitor);
        printf("%s\n", string);
    end:
        cJSON_Delete(monitor);
    }
}

void xwall_default_action(unsigned int default_action)
{
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();

    user2kernel->req.opcode      = XWALL_OP_DEFACT;
    user2kernel->req.msg.def_act = htonl(default_action);
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_OK) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    printf("%s\n", kernel2user.msg);
}

void xwall_read_default_action()
{
    struct kernel2user kernel2user  = {0};
    struct user2kernel *user2kernel = xwall_user2kernel_create();

    user2kernel->req.opcode = XWALL_OP_READDEFACT;
    xwall_user2kernel_send(user2kernel);

    xwall_kernel2user_recv(&kernel2user);
    if (kernel2user.resp.type != XWALL_TYPE_OK) {
        fprintf(stderr, "Wrong response.\n");
        exit(-1);
    }

    printf("%s\n", get_action_from_id(ntohl(*(unsigned int *)kernel2user.msg)));
}

void xwall_add_nat() { return; }

void xwall_del_nat() { return; }

void xwall_read_nat() { return; }

void helper()
{
    fprintf(stderr,
            "usage: xwall_app [-addrule  saddr daddr smask dmask sport[_min "
            "sport_max] dport[_min dport_max] protocol action logging]\n"
            "                 [-delrule  del_idx]\n"
            "                 [-readrule start_idx end_idx]\n"
            "                 [-saverule]\n"
            "                 [-readlog  start_idx end_idx]\n"
            "                 [-clrlog]\n"
            "                 [-readmlog start_idx end_idx]\n"
            "                 [-clrmlog]\n"
            "                 [-readconn]\n"
            "                 [-defact   default_action(accept/drop)]\n"
            "                 [-readdefact]\n");
    fprintf(stderr, "e.g.:  xwall_app -addrule  127.0.0.1 127.0.0.1 "
                    "255.255.255.0 255.255.255.0 any any TCP accept true\n"
                    "                 -delrule  0\n"
                    "                 -readrule 0 10\n"
                    "                 -saverule\n"
                    "                 -readlog  0 10\n"
                    "                 -clrlog\n"
                    "                 -readmlog  0 10\n"
                    "                 -clrmlog\n"
                    "                 -readconn\n"
                    "                 -defact   drop\n"
                    "                 -readdefact\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        helper();
    init_netlink();

    if (strcmp(argv[1], "-addrule") == 0) {
        if (argc != 11 && argc != 13)
            helper();
        struct xwall_rule rule = {0};
        rule.saddr             = inet_addr(argv[2]);
        rule.daddr             = inet_addr(argv[3]);
        rule.smask             = inet_addr(argv[4]);
        rule.dmask             = inet_addr(argv[5]);
        if (rule.saddr == INADDR_NONE || rule.daddr == INADDR_NONE ||
            rule.smask == INADDR_NONE || rule.dmask == INADDR_NONE) {
            printf("Invalid addr and mask.\n");
            helper();
        }
        if (argc == 11) {
            if (strcmp(argv[6], "any") == 0) {
                rule.sport_min = 0;
                rule.sport_max = 0xffffu;
            } else {
                rule.sport_min = rule.sport_max =
                    htons(strtoul(argv[6], NULL, 0));
            }
            if (strcmp(argv[7], "any") == 0) {
                rule.dport_min = 0;
                rule.dport_max = 0xffffu;
            } else {
                rule.dport_min = rule.dport_max =
                    htons(strtoul(argv[7], NULL, 0));
            }
            rule.protocol = get_protocol_from_str(argv[8]);
            rule.action   = htonl(get_action_from_str(argv[9]));
            rule.logging  = get_logging_from_str(argv[10]);
        } else if (argc == 13) {
            rule.sport_min =
                htons(strcmp(argv[6], "any") ? strtoul(argv[6], NULL, 0) : 0);
            rule.sport_max = htons(
                strcmp(argv[7], "any") ? strtoul(argv[7], NULL, 0) : 0xffffu);
            rule.dport_min =
                htons(strcmp(argv[8], "any") ? strtoul(argv[8], NULL, 0) : 0);
            rule.dport_max = htons(
                strcmp(argv[9], "any") ? strtoul(argv[9], NULL, 0) : 0xffffu);
            rule.protocol = get_protocol_from_str(argv[10]);
            rule.action   = htonl(get_action_from_str(argv[11]));
            rule.logging  = get_logging_from_str(argv[12]);
        }
        xwall_add_rule(&rule);
    } else if (strcmp(argv[1], "-delrule") == 0) {
        if (argc < 3)
            helper();
        unsigned int del_idx = strtoul(argv[2], NULL, 0);
        xwall_del_rule(del_idx);
    } else if (strcmp(argv[1], "-readrule") == 0) {
        if (argc < 4)
            helper();
        unsigned int start_idx = strtoul(argv[2], NULL, 0),
                     end_idx   = strtoul(argv[3], NULL, 0);
        if (end_idx <= start_idx || end_idx - start_idx > 100) {
            printf("end_idx must greater than start_idx with sub in 100.\n");
            helper();
        }
        if (argc == 5 && strcmp(argv[4], "-json") == 0) {
            xwall_read_rule(start_idx, end_idx, true);
        } else {
            xwall_read_rule(start_idx, end_idx, false);
        }
    } else if (strcmp(argv[1], "-saverule") == 0) {
        xwall_save_rule();
    } else if (strcmp(argv[1], "-readlog") == 0) {
        if (argc < 4)
            helper();
        unsigned int start_idx = strtoul(argv[2], NULL, 0),
                     end_idx   = strtoul(argv[3], NULL, 0);
        if (end_idx <= start_idx || end_idx - start_idx > 100) {
            printf("end_idx must greater than start_idx with sub in 100.\n");
            helper();
        }
        if (argc == 5 && strcmp(argv[4], "-json") == 0) {
            xwall_read_log(start_idx, end_idx, true);
        } else {
            xwall_read_log(start_idx, end_idx, false);
        }
    } else if (strcmp(argv[1], "-clrlog") == 0) {
        xwall_clear_log();
    } else if (strcmp(argv[1], "-readmlog") == 0) {
        if (argc < 4)
            helper();
        unsigned int start_idx = strtoul(argv[2], NULL, 0),
                     end_idx   = strtoul(argv[3], NULL, 0);
        if (end_idx <= start_idx || end_idx - start_idx > 100) {
            printf("end_idx must greater than start_idx with sub in 100.\n");
            helper();
        }
        if (argc == 5 && strcmp(argv[4], "-json") == 0) {
            xwall_read_mlog(start_idx, end_idx, true);
        } else {
            xwall_read_mlog(start_idx, end_idx, false);
        }
    } else if (strcmp(argv[1], "-readconn") == 0) {
        if (argc == 3 && strcmp(argv[2], "-json") == 0) {
            xwall_read_conn(true);
        } else {
            xwall_read_conn(false);
        }
    } else if (strcmp(argv[1], "-clrmlog") == 0) {
        xwall_clear_mlog();
    } else if (strcmp(argv[1], "-defact") == 0) {
        if (argc < 3)
            helper();
        unsigned int default_action = get_action_from_str(argv[2]);
        xwall_default_action(default_action);
    } else if (strcmp(argv[1], "-readdefact") == 0) {
        xwall_read_default_action();
    } else {
        helper();
    }

    close(sk_nl);
    return 0;
}
