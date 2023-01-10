#define NETLINK_TEST         17
#define XWALL_MANAGE_LOG_LEN 256

#ifdef __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) (((__u64)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((__u64)ntohl((x)&0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

/* Data structures and enumerations. */
struct xwall_connection {
    __be32 saddr;
    __be32 daddr;
    __u8 protocol;
    union {
        struct {
            __u8 type;
            __u8 code;
        } icmp;
        struct {
            __be16 sport;
            __be16 dport;
            __u8 state;
        } tcp;
        struct {
            __be16 sport;
            __be16 dport;
        } udp;
    };
    __be64 timeout; // ktime_t
    struct hlist_node node;
};

struct xwall_rule {
    __be32 idx; // unsigned int
    __be32 saddr;
    __be32 daddr;
    __be32 smask;
    __be32 dmask;
    __be16 sport_min;
    __be16 sport_max;
    __be16 dport_min;
    __be16 dport_max;
    __u8 protocol;
    __be32 action; // unsigned int
    __u8 logging;
    __be64 timeout; // ktime_t
    struct list_head node;
};

struct xwall_log {
    __be32 idx; // unsigned int
    __be64 ts;  // ktime_t
    __be32 saddr;
    __be32 daddr;
    __u8 protocol;
    union {
        struct {
            __u8 type;
            __u8 code;
        } icmp;
        struct {
            __be16 sport;
            __be16 dport;
            __u8 state;
        } tcp;
        struct {
            __be16 sport;
            __be16 dport;
        } udp;
    };
    __be16 len;    // unsigned short
    __be32 action; // unsigned int
    struct list_head node;
};

struct xwall_mlog {
    __be32 idx; // unsigned int
    __be64 ts;  // ktime_t
    __u8 msg[XWALL_MANAGE_LOG_LEN];
    struct list_head node;
};

enum XWALL_REQUEST_OP {
    XWALL_OP_ADDRULE,
    XWALL_OP_DELRULE,
    XWALL_OP_READRULE,
    XWALL_OP_SAVERULE,
    XWALL_OP_READLOG,
    XWALL_OP_CLRLOG,
    XWALL_OP_READMLOG,
    XWALL_OP_CLRMLOG,
    XWALL_OP_READCONN,
    XWALL_OP_DEFACT,
    XWALL_OP_READDEFACT,
    XWALL_OP_ADDNAT,
    XWALL_OP_DELNAT,
    XWALL_OP_READNAT
};

struct xwall_request {
    __u8 opcode;
    union {
        struct xwall_rule rule_add;
        __be32 rule_del_idx; // unsigned int
        struct {
            __be32 start_idx; // unsigned int
            __be32 end_idx;   // unsigned int
        } read_rule, read_log, read_nat, read_mlog;
        __be32 def_act; // unsigned int
    } msg;
};

enum XWALL_RESPONSE_TYPE {
    XWALL_TYPE_OK,
    XWALL_TYPE_ERROR,
    XWALL_TYPE_RULE,
    XWALL_TYPE_LOG,
    XWALL_TYPE_MLOG,
    XWALL_TYPE_CONN,
    XWALL_TYPE_NAT
};

struct xwall_response {
    __u8 type;
    __be32 len;
    __u8 msg[0];
};
