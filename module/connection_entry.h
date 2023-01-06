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
#define CONNECTION_ENTRY_init_by_skb(entry, skb) (_ENTRY_VTBL((entry))->init_by_skb((connection_entry_t *)(entry), (skb)))
#define CONNECTION_ENTRY_init_by_id(entry, id) (_ENTRY_VTBL((entry))->init_by_id((connection_entry_t *)(entry), (id)))
#define CONNECTION_ENTRY_destroy(entry) (_ENTRY_VTBL((entry))->destroy((connection_entry_t *)(entry)))
#define CONNECTION_ENTRY_pre_routing_hook(entry, skb, cmp_result) do {          \
    if (NULL != _ENTRY_VTBL((entry))->pre_routing_hook) {                       \
        _ENTRY_VTBL((entry))->pre_routing_hook((connection_entry_t *)(entry),   \
                                               (skb),                           \
                                               (cmp_result));                   \
    }                                                                           \
} while (0)

#define CONNECTION_ENTRY_local_out_hook(entry, skb, cmp_result) do {        \
    if (NULL != _ENTRY_VTBL((entry))->local_out_hook) {                     \
        _ENTRY_VTBL((entry))->local_out_hook((connection_entry_t *)(entry), \
                                               (skb),                       \
                                               (cmp_result));               \
    }                                                                       \
} while (0)

#define CONNECTION_ENTRY_cmp_pre_routing(entry, skb) (_ENTRY_VTBL((entry))->cmp_pre_routing((connection_entry_t *)(entry), (skb)))
#define CONNECTION_ENTRY_cmp_local_out(entry, skb) (_ENTRY_VTBL((entry))->cmp_local_out((connection_entry_t *)(entry), (skb)))
#define CONNECTION_ENTRY_dump(entry, buf, buflen) (_ENTRY_VTBL((entry))->dump((connection_entry_t *)(entry), (buf), (buflen)))
#define CONNECTION_ENTRY_get_conn_by_cmp(entry, cmp_res, src_out, dst_out) (_ENTRY_VTBL((entry))->get_conn_by_cmp((entry), (cmp_res), (src_out), (dst_out)))
#define CONNECTION_ENTRY_is_closed(entry) (_ENTRY_VTBL((entry))->is_closed((connection_entry_t *)(entry)))

#define IS_PROXY_ENTRY(entry) (CONNECTION_TYPE_PROXY == _ENTRY_VTBL((entry))->type)

#define CMP_IS_SERVER_TO_CLIENT(cmp) ((PACKET_DIRECTION_FROM_SERVER == (cmp)) || (PACKET_DIRECTION_TO_CLIENT == (cmp)))

/*   E N U M S   */
typedef enum connection_type_e {
    CONNECTION_TYPE_DIRECT = 0,
    CONNECTION_TYPE_PROXY
} connection_type_t;

typedef enum packet_direction_e {
    PACKET_DIRECTION_MISMATCH = 0,
    PACKET_DIRECTION_FROM_CLIENT,
    PACKET_DIRECTION_FROM_SERVER,
    PACKET_DIRECTION_TO_SERVER, /* Proxy -> server */
    PACKET_DIRECTION_TO_CLIENT, /* Proxy -> client */
} packet_direction_t;


/*   T Y P E D E F S   */
typedef struct connection_s connection_t;
typedef struct proxy_connection_s proxy_connection_t;
typedef struct connection_id_s connection_id_t;
typedef struct single_connection_s single_connection_t;
typedef struct connection_entry_s connection_entry_t;
typedef struct proxy_connection_entry_s proxy_connection_entry_t;
typedef result_t (*entry_create_f)(connection_entry_t **entry_out);
typedef void (*entry_init_by_id_f)(connection_entry_t *entry,
                                   const connection_id_t *id);
typedef void (*entry_init_by_skb_f)(connection_entry_t *entry,
                                    const struct sk_buff *skb);
typedef void (*entry_destroy_f)(connection_entry_t *entry);

typedef void (*entry_hook_f)(connection_entry_t *conn,
                             struct sk_buff *skb,
                             packet_direction_t cmp_result);

typedef packet_direction_t (*entry_compare_f)(connection_entry_t *conn,
                                              const struct sk_buff *skb);
typedef bool_t (*get_conn_by_cmp_f)(connection_entry_t *entry,
                                    packet_direction_t cmp_res,
                                    single_connection_t **src_out,
                                    single_connection_t **dst_out);

typedef size_t (*dump_entry_f)(const connection_entry_t *entry,
                             uint8_t *buffer,
                             size_t buffer_size);


typedef bool_t (*entry_is_closed_f)(connection_entry_t *entry);

/*   S T R U C T S   */
typedef struct connection_entry_vtbl_s {
    connection_type_t type;
    entry_create_f create;
    entry_destroy_f destroy;
    entry_is_closed_f is_closed;
    entry_init_by_skb_f init_by_skb;
    entry_init_by_id_f init_by_id;
    entry_hook_f pre_routing_hook;
    entry_hook_f local_out_hook;
    entry_compare_f cmp_pre_routing;
    entry_compare_f cmp_local_out;
    dump_entry_f dump;
    get_conn_by_cmp_f get_conn_by_cmp;
} connection_entry_vtbl_t;

#pragma pack(1)
struct connection_id_s {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
};

#pragma pack(1)
struct single_connection_s {
    connection_id_t id;
    __u8 state;
};

#pragma pack(1)
typedef struct connection_s {
    single_connection_t opener;
    single_connection_t listener;
} connection_t;

#pragma pack(1)
typedef struct proxy_connection_s {
    single_connection_t opener;
    single_connection_t listener;
    __u16 proxy_port;
} proxy_connection_t;

struct connection_entry_s {
    struct klist_node node;
    connection_entry_vtbl_t *_vtbl;
    connection_t *conn;
};

struct proxy_connection_entry_s {
    struct klist_node node;
    connection_entry_vtbl_t *_vtbl;
    union {
        proxy_connection_t *client_conn;
        connection_t *client_conn_nonproxy;
    };
    union {
        proxy_connection_t *server_conn;
        connection_t *server_conn_nonproxy;
    };
};




/*   G L O B A L S   */
extern connection_entry_vtbl_t g_vtable_connection_direct;
extern connection_entry_vtbl_t g_vtable_connection_proxy;


/*   F U N C T I O N S   D E C L A R A T I O N S   */

result_t
CONNECTION_ENTRY_create_from_syn(connection_entry_t **entry_out,
                                  const struct sk_buff *skb);

result_t
CONNECTION_ENTRY_create_from_id(connection_entry_t **entry_out,
                                const connection_id_t *id);

const char *
ENTRY_str(const connection_entry_t *ent);

const char *
CONN_str(const connection_t *conn);

const char *
SINGLE_CONN_str(const single_connection_t *conn);

packet_direction_t
CONNECTION_compare(const connection_t *conn,
                   const struct sk_buff *skb);


#endif /* __CONNECTION_ENTRY_H__ */

