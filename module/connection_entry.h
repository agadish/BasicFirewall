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

#include "connection.h"
#include "fw.h"
#include "fw_results.h"


/*   C O N S T A N T S   */
#define HTTP_PORT_N (htons(80))
#define HTTP_USER_PORT_N (htons(800))
#define FTP_PORT_N (htons(21))
#define FTP_USER_PORT_N (htons(210))


/*   M A C R O S   */
/* Vtable syntactic sugar */
#define _ENTRY_VTBL(entry) (((connection_entry_t *)(entry))->_vtbl)
#define CONNECTION_ENTRY_init_by_skb(entry, skb) \
    (_ENTRY_VTBL((entry))->init_by_skb((connection_entry_t *)(entry), (skb)))

#define CONNECTION_ENTRY_init_by_id(entry, id) \
    (_ENTRY_VTBL((entry))->init_by_id((connection_entry_t *)(entry), (id)))

#define CONNECTION_ENTRY_destroy(entry) \
    (_ENTRY_VTBL((entry))->destroy((connection_entry_t *)(entry)))

#define CONNECTION_ENTRY_pre_routing_hook(ent, skb, direction) do {         \
    if (NULL != _ENTRY_VTBL((ent))->pre_routing_hook) {                     \
        _ENTRY_VTBL((ent))->pre_routing_hook((connection_entry_t *)(ent),   \
                                             (skb),                         \
                                             (direction));                  \
    }                                                                       \
} while (0)

#define CONNECTION_ENTRY_local_out_hook(entry, skb, direction) do {         \
    if (NULL != _ENTRY_VTBL((entry))->local_out_hook) {                     \
        _ENTRY_VTBL((entry))->local_out_hook((connection_entry_t *)(entry), \
                                               (skb),                       \
                                               (direction));                \
    }                                                                       \
} while (0)

#define CONNECTION_ENTRY_cmp_pre_routing(entry, skb) \
    (_ENTRY_VTBL((entry))->cmp_pre_routing((connection_entry_t *)(entry), \
                                           (skb)))

#define CONNECTION_ENTRY_cmp_local_out(entry, skb) \
    (_ENTRY_VTBL((entry))->cmp_local_out((connection_entry_t *)(entry), (skb)))

#define CONNECTION_ENTRY_dump(entry, buf, buflen) \
    (_ENTRY_VTBL((entry))->dump((connection_entry_t *)(entry), (buf), (buflen)))

#define CONNECTION_ENTRY_get_conns_by_direction(entry, dir, src_out, dst_out) \
    (_ENTRY_VTBL((entry))->get_conns_by_direction((entry), \
                                                  (dir), \
                                                  (src_out), \
                                                  (dst_out)))

#define CONNECTION_ENTRY_is_closed(entry) \
    (_ENTRY_VTBL((entry))->is_closed((connection_entry_t *)(entry)))

#define IS_PROXY_ENTRY(entry) (CONNECTION_TYPE_PROXY == \
                               _ENTRY_VTBL((entry))->type)

#define CMP_IS_SERVER_TO_CLIENT(cmp) ((PACKET_DIRECTION_FROM_SERVER == (cmp)) \
                                      || (PACKET_DIRECTION_TO_CLIENT == (cmp)))


/*   E N U M S   */
typedef enum packet_direction_e {
    PACKET_DIRECTION_MISMATCH = 0,
    PACKET_DIRECTION_FROM_CLIENT,
    PACKET_DIRECTION_FROM_SERVER,
    PACKET_DIRECTION_TO_SERVER, /* Proxy -> server */
    PACKET_DIRECTION_TO_CLIENT, /* Proxy -> client */
} packet_direction_t;


/*   T Y P E D E F S   */
typedef struct connection_entry_s connection_entry_t;
typedef struct proxy_connection_entry_s proxy_connection_entry_t;

/**
 * @brief Allocate a new connection entry
 * 
 * @param[out] entry_out The new entry
 *
 * @return E__SUCCESS on success, other result_t value on failure
 */
typedef result_t (*entry_create_f)(connection_entry_t **entry_out);

/**
 * @brief Initialise an entry's connection by a given ID
 *
 * @param[in] entry The entry to init
 * @param[in] id The id to use to init
 */
typedef void (*entry_init_by_id_f)(connection_entry_t *entry,
                                   const connection_id_t *id);

/**
 * @brief Initialise an entry's connection by a given skb
 *
 * @param[in] entry The entry to init
 * @param[in] skb The skb to use to init
 */
typedef void (*entry_init_by_skb_f)(connection_entry_t *entry,
                                    const struct sk_buff *skb);

/**
 * @brief Destroy an entry that was allocated using
 *        CONNECTION_ENTRY_create_from(skb|id)
 *
 * @param[in] entry Entry to destroy
 */
typedef void (*entry_destroy_f)(connection_entry_t *entry);

/**
 * @brief Hook a given packet that matches the entry from a given direction
 *
 * @param[in] entry The entry that matches that packet
 * @param[in] skb The packet
 * @param[in] direction The direction on which the packet belongs to
 */
typedef void (*entry_hook_f)(connection_entry_t *entry,
                             struct sk_buff *skb,
                             packet_direction_t direction);

/**
 * @brief Check if a given packet refers to our entry and get the matching
 *        direction
 *
 * @param[in] entry The entry
 * @param[in] skb The packet
 *
 * @return PACKET_DIRECTION_MISMATCH    if doesn't match
 *         PACKET_DIRECTION_FROM_CLIENT if the packet is from client to proxy
 *         PACKET_DIRECTION_FROM_SERVER if the packet is from server to proxy
 *         PACKET_DIRECTION_TO_CLIENT   if the packet is from proxy to client
 *         PACKET_DIRECTION_TO_SERVER   if the packet is from proxy to server
 */
typedef packet_direction_t (*entry_compare_f)(connection_entry_t *entry,
                                              const struct sk_buff *skb);

/**
 * @brief Given an entry and a packet direction, get the two single_connection_t
 *        that matches the source and the destination of that direction
 *
 * @param[in] entry The entry
 * @param[in] direction The direction
 * @param[out] src_out The single_connection_t that matches the source
 * @param[out] dst_out The single_connection_t that matches the dest
 *
 * @return TRUE on success, FALSE on failure
 */
typedef bool_t (*get_conns_by_direction_f)(connection_entry_t *entry,
                                           packet_direction_t direction,
                                           single_connection_t **src_out,
                                           single_connection_t **dst_out);

/**
 * @brief Write the entry in a binary format to a given buffer.
 *        CONNECTION_TYPE_DIRECT entries have the ID and their state, and
 *        CONNECTION_TYPE_PROXY entries have two instances of ID+state for both
 *        client_conn and server_conn
 *
 * @param[in] entry The entry to dump
 * @param[out] buffer The buffer to write to
 * @param[in] buffer_size Size of buffer
 */
typedef size_t (*dump_entry_f)(const connection_entry_t *entry,
                               uint8_t *buffer,
                               size_t buffer_size);

/**
 * @brief Check if an entry is closed, aka all its connections have state
 *        TCP_CLOSE
 *
 * @param[in] entry The entry to check
 *
 * @return TRUE if is closed, otherwise FALSE
 *
 */
typedef bool_t (*entry_is_closed_f)(connection_entry_t *entry);


/*   S T R U C T S   */
/**
 * @brief The functions that every connection_entry_t need to implement
 *
 * @param type The type of the connection, a connection_type_t value
 * @param create A function that allocates and returns the entry
 * @param destroy A function that frees a previously allocated entry
 * @param is_closed Check if the connection is opened or closed
 * @param init_by_skb Initialise an entry using a packet of opener->listener
 * @param init_by_id Initialise an entry using a connection_id_t value
 * @param pre_routing_hook A hook to be called during NF's PRE_ROUTING
 * @param local_out_hook A hook to be called during NF's LOCAL_OUT
 * @param cmp_pre_routing Check a PRE_ROUTING packet's direction
 * @param cmp_local_out Check a LOCAL_OUT packet's direction
 * @param dump Copy the entry to a buffer in a binary format
 * @param get_conns_by_direction Get the source and dest of a given direction
 */
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
    get_conns_by_direction_f get_conns_by_direction;
} connection_entry_vtbl_t;

/** @brief An entry of connection in the connections table, that belongs to
 *         a CONNECTION_TYPE_DIRECT connection */
struct connection_entry_s {
    struct klist_node node;
    connection_entry_vtbl_t *_vtbl;
    connection_t *conn;
};

/** @brief An entry of connection in the connections table, that belongs to
 *         a CONNECTION_TYPE_PROXY connection */
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
/** @brief The VTABLE instance with the functions for CONNECTION_TYPE_DIRECT */
extern connection_entry_vtbl_t g_vtable_connection_direct;

/** @brief The VTABLE instance with the functions for CONNECTION_TYPE_PROXY */
extern connection_entry_vtbl_t g_vtable_connection_proxy;


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief A factroy method that creates a new connection from a given packet.
 *        The new connection can be either direct or proxy, depending on the
 *        TCP destination port within the packet
 *
 * @param[out] entry_out The new entry
 * @param[in] skb The packet
 *
 * @return E__SUCCESS on success, other result_t value on failure
 */
result_t
CONNECTION_ENTRY_create_from_skb(connection_entry_t **entry_out,
                                  const struct sk_buff *skb);

/**
 * @brief A factroy method that creates a new connection from a given ID.
 *        The new connection can be either direct or proxy, depending on
 *        id->dest_port
 *
 * @param[out] entry_out The new entry
 * @param[in] id The given id
 *
 * @return E__SUCCESS on success, other result_t value on failure
 */
result_t
CONNECTION_ENTRY_create_from_id(connection_entry_t **entry_out,
                                const connection_id_t *id);

/** @brief Debug function */
const char *
ENTRY_str(const connection_entry_t *ent);

/** @brief Debug function */
const char *
CONN_str(const connection_t *conn);

/** @brief Debug function */
const char *
SINGLE_CONN_str(const single_connection_t *conn);


#endif /* __CONNECTION_ENTRY_H__ */

