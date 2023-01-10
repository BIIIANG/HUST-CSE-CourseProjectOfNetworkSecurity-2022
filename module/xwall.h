#include <linux/hashtable.h>
#include <linux/icmp.h>

#include "xwall_public.h"

// #define XWALL_RULE_FILE      "./xwall.rule"
#define XWALL_RULE_FILE      "/tmp/xwall.rule"
#define XWALL_RULE_FILE_PRIV 0644

#define XWALL_HASHTABLE_BITS          (10)
#define XWALL_CLEAN_CONN_INVERVAL_SEC (10)
#define XWALL_LAN_PORT_ICMP           (11803)
#define XWALL_NAT_PORT_START          (11803 + 1)
#define XWALL_MAX_NAT_ENTRY_NUM       (65536)

#define ip_to_be32(a, b, c, d) (a + (b << 8) + (c << 16) + (d << 24))

/* Data structures. */
struct xwall_index {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __u8 padding[15];
};

struct xwall_hashtable {
    rwlock_t lock;
    unsigned int conn_num;
    DECLARE_HASHTABLE(hashtable, XWALL_HASHTABLE_BITS);
};

struct xwall_ruletable {
    rwlock_t lock;
    unsigned int rule_num;
    struct list_head node;
};

struct xwall_logtable {
    struct mutex lock;
    unsigned int log_num;
    struct list_head node;
};

struct xwall_mlogtable {
    struct mutex lock;
    unsigned int log_num;
    struct list_head node;
};

struct xwall_nat {
    ktime_t timeout;
    __be32 lan_addr;
    __be16 lan_port;
    bool valid;
};

/* Hash function (Jenkins).
 * REFE: https://troydhanson.github.io/uthash/userguide.html#hash_functions */
#define HASH_JEN_MIX(a, b, c)                                                  \
    do {                                                                       \
        a -= b;                                                                \
        a -= c;                                                                \
        a ^= (c >> 13);                                                        \
        b -= c;                                                                \
        b -= a;                                                                \
        b ^= (a << 8);                                                         \
        c -= a;                                                                \
        c -= b;                                                                \
        c ^= (b >> 13);                                                        \
        a -= b;                                                                \
        a -= c;                                                                \
        a ^= (c >> 12);                                                        \
        b -= c;                                                                \
        b -= a;                                                                \
        b ^= (a << 16);                                                        \
        c -= a;                                                                \
        c -= b;                                                                \
        c ^= (b >> 5);                                                         \
        a -= b;                                                                \
        a -= c;                                                                \
        a ^= (c >> 3);                                                         \
        b -= c;                                                                \
        b -= a;                                                                \
        b ^= (a << 10);                                                        \
        c -= a;                                                                \
        c -= b;                                                                \
        c ^= (b >> 15);                                                        \
    } while (0)

#define HASH_JEN(key, keylen, hashv)                                           \
    do {                                                                       \
        unsigned _hj_i, _hj_j, _hj_k;                                          \
        unsigned const char *_hj_key = (unsigned const char *)(key);           \
        hashv                        = 0xfeedbeefu;                            \
        _hj_i = _hj_j = 0x9e3779b9u;                                           \
        _hj_k         = (unsigned)(keylen);                                    \
        while (_hj_k >= 12U) {                                                 \
            _hj_i +=                                                           \
                (_hj_key[0] + ((unsigned)_hj_key[1] << 8) +                    \
                 ((unsigned)_hj_key[2] << 16) + ((unsigned)_hj_key[3] << 24)); \
            _hj_j +=                                                           \
                (_hj_key[4] + ((unsigned)_hj_key[5] << 8) +                    \
                 ((unsigned)_hj_key[6] << 16) + ((unsigned)_hj_key[7] << 24)); \
            hashv += (_hj_key[8] + ((unsigned)_hj_key[9] << 8) +               \
                      ((unsigned)_hj_key[10] << 16) +                          \
                      ((unsigned)_hj_key[11] << 24));                          \
                                                                               \
            HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                 \
                                                                               \
            _hj_key += 12;                                                     \
            _hj_k -= 12U;                                                      \
        }                                                                      \
        hashv += (unsigned)(keylen);                                           \
        switch (_hj_k) {                                                       \
        case 11:                                                               \
            hashv += ((unsigned)_hj_key[10] << 24);                            \
            fallthrough;                                                       \
        case 10:                                                               \
            hashv += ((unsigned)_hj_key[9] << 16);                             \
            fallthrough;                                                       \
        case 9:                                                                \
            hashv += ((unsigned)_hj_key[8] << 8);                              \
            fallthrough;                                                       \
        case 8:                                                                \
            _hj_j += ((unsigned)_hj_key[7] << 24);                             \
            fallthrough;                                                       \
        case 7:                                                                \
            _hj_j += ((unsigned)_hj_key[6] << 16);                             \
            fallthrough;                                                       \
        case 6:                                                                \
            _hj_j += ((unsigned)_hj_key[5] << 8);                              \
            fallthrough;                                                       \
        case 5:                                                                \
            _hj_j += _hj_key[4];                                               \
            fallthrough;                                                       \
        case 4:                                                                \
            _hj_i += ((unsigned)_hj_key[3] << 24);                             \
            fallthrough;                                                       \
        case 3:                                                                \
            _hj_i += ((unsigned)_hj_key[2] << 16);                             \
            fallthrough;                                                       \
        case 2:                                                                \
            _hj_i += ((unsigned)_hj_key[1] << 8);                              \
            fallthrough;                                                       \
        case 1:                                                                \
            _hj_i += _hj_key[0];                                               \
            fallthrough;                                                       \
        default:;                                                              \
        }                                                                      \
        HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                     \
    } while (0)

#define XWALL_HASH_JEN(keyptr, keylen, hashv, bits)                            \
    do {                                                                       \
        HASH_JEN(keyptr, keylen, hashv);                                       \
        hashv >>= (32 - bits);                                                 \
    } while (0)

/* Match package and connection. */
#define existing_connection_tcp(old_conn, new_conn)                            \
    (old_conn->saddr == new_conn->saddr &&                                     \
     old_conn->daddr == new_conn->daddr &&                                     \
     old_conn->tcp.sport == new_conn->tcp.sport &&                             \
     old_conn->tcp.dport == new_conn->tcp.dport)

#define existing_connection_others(old_conn, new_conn)                         \
    ((old_conn->saddr == new_conn->saddr &&                                    \
      old_conn->daddr == new_conn->daddr) ||                                   \
     (old_conn->saddr == new_conn->daddr &&                                    \
      old_conn->daddr == new_conn->saddr))

/* Function declaration. */
void xwall_hashtable_clean(struct xwall_hashtable *table);
void xwall_hashtable_clear(struct xwall_hashtable *table);
struct xwall_mlog *xwall_mlog_create(void);
struct xwall_mlogtable *xwall_mlogtable_create(void);
void xwall_mlogtable_add(struct xwall_mlogtable *table,
                         struct xwall_mlog *mlog);
char *xwall_mlogtable_read(struct xwall_mlogtable *table,
                           unsigned int start_idx, unsigned int end_idx,
                           int *len);
void xwall_mlogtable_clear(struct xwall_mlogtable *table);

unsigned int xwall_filter(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state);
unsigned int xwall_filter_out(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state);
unsigned int xwall_nat_in(void *priv, struct sk_buff *skb,
                          const struct nf_hook_state *state);
unsigned int xwall_nat_out(void *priv, struct sk_buff *skb,
                           const struct nf_hook_state *state);