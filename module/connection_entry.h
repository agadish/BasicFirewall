/**
 * @file connection_entry.h
 * @author Assaf Gadish
 *
 * @brief ConnectionEntry functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
#ifndef __CONNECTION_ENTRY_H__
#define __CONNECTION_ENTRY_H__

/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>

#include "fw.h"
#include "fw_results.h"


/*   C O N S T A N T S   */
#define HTTP_PORT_N (htons(80))
#define HTTP_USER_PORT_N (htons(800))
#define FTP_PORT_N (htons(21))
#define FTP_USER_PORT_N (htons(210))

/*   M A C R O S   */
#define _ENTRY_VTBL(entry) (((connection_entry_t *)(entry))->_vtbl)
#define CONNECTION_ENTRY_init_by_skb(entry, skb) (_ENTRY_VTBL((entry))->init_by_skb((entry), (skb)))
// #define CONNECTION_ENTRY_init_by_id(entry, id) (_ENTRY_VTBL((entry))->init_by_id((entry), (id)))
#define CONNECTION_ENTRY_hook(entry, skb) (_ENTRY_VTBL((entry))->hook((entry), (skb)))
#define CONNECTION_ENTRY_compare(entry, skb) (_ENTRY_VTBL((entry))->compare((entry), (skb)))
#define CONNECTION_ENTRY_connection_alloc(conn_out) (_ENTRY_VTBL((entry))->connection_alloc(conn_out))
#define IS_PROXY_ENTRY(entry) (CONNECTION_TYPE_PROXY == _ENTRY_VTBL((entry))->type)


/*   E N U M S   */
typedef enum connection_type_e {
    CONNECTION_TYPE_DIRECT = 0,
    CONNECTION_TYPE_PROXY
} connection_type_t;

typedef enum entry_cmp_result_e {
    ENTRY_CMP_MISMATCH = 0,
    ENTRY_CMP_FROM_CLIENT,
    ENTRY_CMP_FROM_SERVER,
    ENTRY_CMP_TO_SERVER, /* Proxy -> server */
    ENTRY_CMP_TO_CLIENT, /* Proxy -> client */
} entry_cmp_result_t;


/*   T Y P E D E F S   */
typedef struct connection_entry_s connection_entry_t;
typedef struct connection_id_s connection_id_t;
typedef struct connection_s connection_t;
typedef void (*entry_init_by_skb_f)(connection_entry_t *entry,
                                    const struct sk_buff *skb);
// typedef void (*entry_init_by_id_f)(connection_entry_t *entry,
//                                    const connection_id_t *id);

typedef void (*entry_hook_f)(connection_entry_t *conn,
                             struct sk_buff *skb);

typedef entry_cmp_result_t (*entry_compare_f)(connection_entry_t *conn,
                                              const struct sk_buff *skb);

typedef result_t (*connection_alloc_f)(connection_t **conn_out);


/*   S T R U C T S   */
typedef struct connection_entry_vtbl_s {
    connection_type_t type;
    connection_alloc_f connection_alloc;
    entry_init_by_skb_f init_by_skb;
    // entry_init_by_id_f init_by_id;
    entry_hook_f hook;
    entry_compare_f compare;
} connection_entry_vtbl_t;

#pragma pack(1)
struct connection_id_s {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
};

#pragma pack(1)
struct connection_s {
    connection_id_t id;
    __u8 state;
};

#pragma pack(1)
typedef struct proxy_connection_s {
    connection_t base;
    __u16 proxy_port;
} proxy_connection_t;

struct connection_entry_s {
    struct klist_node node;
    connection_entry_vtbl_t *_vtbl;
    union {
        connection_t *client;
        proxy_connection_t *client_proxy;
    };
    union {
        connection_t *server;
        proxy_connection_t *server_proxy;
    };
};




/*   G L O B A L S   */
extern connection_entry_vtbl_t g_vtable_connection_direct;
extern connection_entry_vtbl_t g_vtable_connection_proxy;


/*   F U N C T I O N S   D E C L A R A T I O N S   */

result_t
CONNECTION_ENTRY_create_from_syn(connection_entry_t **entry_out,
                                  const struct sk_buff *skb);
void
CONNECTION_ENTRY_destroy(connection_entry_t *entry);

const char *
SKB_str(const struct sk_buff *skb);


#endif /* __CONNECTION_ENTRY_H__ */

