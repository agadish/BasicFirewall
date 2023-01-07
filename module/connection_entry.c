/**
 * @file connection_entry.c
 * @author Assaf Gadish
 *
 * @brief Connection functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <linux/ip.h>

#include "common.h"
#include "net_utils.h"
#include "fw.h"
#include "fw_results.h"
#include "connection.h"

#include "connection_entry.h"


/*   M A C R O S   */
#define IS_SCONN_CLOSED(sconn) (TCP_CLOSE == (sconn).state)
#define CONNECTION_IS_CLOSED(conn) (IS_SCONN_CLOSED((conn)->opener) && \
                                    IS_SCONN_CLOSED((conn)->listener))


/*   F U N C T I O N S   D E C L A R A T I O N S   */
static void
entry_init_by_skb(connection_entry_t *entry,
                  const struct sk_buff *skb);

static void
entry_init_by_id(connection_entry_t *entry,
                 const connection_id_t *id);

static void
proxy_entry_init_by_skb(proxy_connection_entry_t *entry,
                        const struct sk_buff *skb);

static void
proxy_entry_init_by_id(proxy_connection_entry_t *entry,
                       const connection_id_t *id);

static void
proxy_init_proxy_ports(proxy_connection_entry_t *entry,
                       uint16_t dst_port_n);

static void
proxy_entry_pre_routing_hook(proxy_connection_entry_t *entry,
                           struct sk_buff *skb,
                           packet_direction_t skb_cmp_result);

static void
proxy_entry_local_out_hook(proxy_connection_entry_t *entry,
                           struct sk_buff *skb,
                           packet_direction_t skb_cmp_result);

static packet_direction_t
entry_compare_packet_pre_routing(connection_entry_t *entry,
                                 const struct sk_buff *skb);

static packet_direction_t
entry_compare_packet_local_out(connection_entry_t *entry,
                               const struct sk_buff *skb);

static packet_direction_t
proxy_entry_compare_packet_pre_routing(proxy_connection_entry_t *entry,
                                       const struct sk_buff *skb);

static packet_direction_t
proxy_entry_compare_packet_local_out(proxy_connection_entry_t *entry,
                                     const struct sk_buff *skb);


/**
 * @remark The returned entry must be freed by calling entry_destory
 */
static result_t
entry_create(connection_entry_t **entry_out);

/**
 * @remark The returned pentry must be freed by calling proxy_entry_destroy
 */
static result_t
proxy_entry_create(proxy_connection_entry_t **pentry_out);

static bool_t
proxy_entry_is_to_client(proxy_connection_entry_t *pentry,
                         const struct sk_buff *skb);

static bool_t
proxy_entry_is_to_server(proxy_connection_entry_t *pentry,
                         const struct sk_buff *skb);

static void
entry_destroy(connection_entry_t *entry);

static void
proxy_entry_destroy(proxy_connection_entry_t *pentry);


static size_t
dump_entry(const connection_entry_t *entry,
           uint8_t *buffer,
           size_t buffer_size);

static size_t
dump_proxy_entry(const proxy_connection_entry_t *pentry,
                 uint8_t *buffer,
                 size_t buffer_size);

static bool_t
entry_get_conns_by_direction(connection_entry_t *entry,
                             packet_direction_t cmp_res,
                             single_connection_t **src_out,
                             single_connection_t **dst_out);

static bool_t
proxy_entry_get_conns_by_direction(proxy_connection_entry_t *entry,
                                   packet_direction_t cmp_res,
                                   single_connection_t **src_out,
                                   single_connection_t **dst_out);
static bool_t
entry_is_closed(connection_entry_t *entry);

static bool_t
proxy_entry_is_closed(proxy_connection_entry_t *entry);


/* static void */
/* CONNECTION_init_by_inverse_conn(connection_t *conn, */
/*                           const connection_t *inverse_conn); */

char g_skb_string_buff[1024];
char g_singleconn_string_buff[1024];
char g_conn_string_buff[1024];
char g_entry_string_buff[1024];

/*   G L O B A L S   */
connection_entry_vtbl_t g_vtable_connection_direct = {
    .type = CONNECTION_TYPE_DIRECT,
    .create = entry_create,
    .destroy = entry_destroy,
    .is_closed = entry_is_closed,
    .init_by_skb = entry_init_by_skb,
    .init_by_id = entry_init_by_id,
    .pre_routing_hook = NULL,
    .local_out_hook = NULL,
    .dump = dump_entry,
    .get_conns_by_direction = entry_get_conns_by_direction,
    .cmp_pre_routing = entry_compare_packet_pre_routing,
    .cmp_local_out = entry_compare_packet_local_out
};

connection_entry_vtbl_t g_vtable_connection_proxy = {
    .type = CONNECTION_TYPE_PROXY,
    .create = (entry_create_f)proxy_entry_create,
    .destroy = (entry_destroy_f)proxy_entry_destroy,
    .is_closed = (entry_is_closed_f)proxy_entry_is_closed,
    .init_by_skb = (entry_init_by_skb_f)proxy_entry_init_by_skb,
    .init_by_id = (entry_init_by_id_f)proxy_entry_init_by_id,
    .pre_routing_hook = (entry_hook_f)proxy_entry_pre_routing_hook,
    .local_out_hook = (entry_hook_f)proxy_entry_local_out_hook,
    .dump = (dump_entry_f)dump_proxy_entry,
    .get_conns_by_direction = (get_conns_by_direction_f)proxy_entry_get_conns_by_direction,
    .cmp_pre_routing = (entry_compare_f)proxy_entry_compare_packet_pre_routing,
    .cmp_local_out = (entry_compare_f)proxy_entry_compare_packet_local_out
};


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
static result_t
entry_create(connection_entry_t **entry_out)
{
    result_t result = E__UNKNOWN;
    connection_entry_t *entry = NULL;

    /* 0. Input validation */
    if (NULL == entry_out) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Allocate a new entry*/
    entry = (connection_entry_t *)kmalloc(sizeof(*entry), GFP_KERNEL);
    if (NULL == entry) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }
    (void)memset(entry, 0, sizeof(*entry));

    /* 2. Allocate connection */
    entry->conn = (connection_t *)kmalloc(sizeof(*entry->conn), GFP_KERNEL);
    if (NULL == entry->conn) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }
    (void)memset(entry->conn, 0, sizeof(*entry->conn));

    /* 3. Assign vable */
    entry->_vtbl = &g_vtable_connection_direct;

    /* Success */
    *entry_out = entry;

    result = E__SUCCESS;
l_cleanup:
    if (E__SUCCESS != result) {
        entry_destroy(entry);
    }
    
    return result;
}

static result_t
proxy_entry_create(proxy_connection_entry_t **pentry_out)
{
    result_t result = E__UNKNOWN;
    proxy_connection_entry_t *pentry = NULL;

    /* 0. Input validation */
    if (NULL == pentry_out) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Allocate a new entry*/
    pentry = (proxy_connection_entry_t *)kmalloc(sizeof(*pentry), GFP_KERNEL);
    if (NULL == pentry) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }
    (void)memset(pentry, 0, sizeof(*pentry));

    /* 2. Allocate connections */
    /* 2.1. Allocate client connection */
    pentry->client_conn = (proxy_connection_t *)kmalloc(sizeof(*pentry->client_conn), GFP_KERNEL);
    if (NULL == pentry->client_conn) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }
    (void)memset(pentry->client_conn, 0, sizeof(*pentry->client_conn));

    /* 2.2. Allocate server connection */
    pentry->server_conn = (proxy_connection_t *)kmalloc(sizeof(*pentry->server_conn), GFP_KERNEL);
    if (NULL == pentry->server_conn) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }
    (void)memset(pentry->server_conn, 0, sizeof(*pentry->server_conn));

    /* 3. Assign vable */
    pentry->_vtbl = &g_vtable_connection_proxy;

    /* Success */
    *pentry_out = pentry;

    result = E__SUCCESS;
l_cleanup:
    if (E__SUCCESS != result) {
        proxy_entry_destroy(pentry);
    }
    
    return result;
}

static void
entry_init_by_skb(connection_entry_t *entry,
                  const struct sk_buff *skb)
{
    if ((NULL != entry) && (NULL != skb)) {
        CONNECTION_init_by_skb(entry->conn, skb);
    }
}

static void
entry_init_by_id(connection_entry_t *entry,
                 const connection_id_t *id)
{
    if ((NULL != entry) && (NULL != id)) {
        CONNECTION_init_by_id(entry->conn, id);
    }
}

static void
proxy_entry_init_by_skb(proxy_connection_entry_t *entry,
                        const struct sk_buff *skb)
{
    struct tcphdr *tcp_header = NULL;

    /* 0. Input validation */
    if ((NULL == entry) || (NULL == skb)) {
        goto l_cleanup;
    }

    tcp_header = tcp_hdr(skb);
    /* 1. Init connections */
    CONNECTION_init_by_skb((connection_t *)entry->client_conn, skb);
    CONNECTION_init_by_skb((connection_t *)entry->server_conn, skb);

    /* 2. Proxy ports */
    proxy_init_proxy_ports(entry, tcp_header->dest);

l_cleanup:
    return;
}

static void
proxy_entry_init_by_id(proxy_connection_entry_t *entry,
                       const connection_id_t *id)
{
    /* 0. Input validation */
    if ((NULL == entry) || (NULL == id)) {
        goto l_cleanup;
    }

    /* 1. Init connections */
    CONNECTION_init_by_id((connection_t *)entry->client_conn, id);
    CONNECTION_init_by_id((connection_t *)entry->server_conn, id);

    /* 2. Proxy ports */
    proxy_init_proxy_ports(entry, id->dst_port);

l_cleanup:
    return;
}

static void
proxy_init_proxy_ports(proxy_connection_entry_t *entry,
                       uint16_t dst_port_n)
{
    switch (dst_port_n) 
    {
        case HTTP_PORT_N:
            printk(KERN_INFO "%s: hello port 80\n", __func__);
            entry->client_conn->proxy_port = HTTP_USER_PORT_N;
            entry->server_conn->proxy_port = 0; /* Will be set later */
            break;
        case FTP_PORT_N:
            printk(KERN_INFO "%s: hello port 21\n", __func__);
            entry->client_conn->proxy_port = FTP_USER_PORT_N;
            entry->server_conn->proxy_port = 0; /* Will be set later */
            break;
        default:
            printk(KERN_ERR "%s: got port that is not HTTP/FTP: %d\n", __func__, ntohs(dst_port_n));
            break;
    }
}

static packet_direction_t
entry_compare_packet_pre_routing(connection_entry_t *entry,
                                 const struct sk_buff *skb)
{
    packet_direction_t result = PACKET_DIRECTION_MISMATCH;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    if ((NULL == entry) || (NULL == skb)) {
        printk(KERN_ERR "%s: got invalid input\n", __func__);
        goto l_cleanup;
    }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);
    if (CONNECTION_does_id_match_skb(&entry->conn->opener.id, skb)) {
        /* Client to proxy */
        result = PACKET_DIRECTION_FROM_CLIENT;
    } else if (CONNECTION_does_id_match_skb(&entry->conn->listener.id, skb)) {
        /* Server to proxy */
        result = PACKET_DIRECTION_FROM_SERVER;
    }

l_cleanup:

    return result;
}

static packet_direction_t
proxy_entry_compare_packet_pre_routing(proxy_connection_entry_t *pentry,
                                       const struct sk_buff *skb)
{
    packet_direction_t result = PACKET_DIRECTION_MISMATCH;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    if ((NULL == pentry) || (NULL == skb)) {
        printk(KERN_ERR "%s: got invalid input\n", __func__);
        goto l_cleanup;
    }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);
    /* Note: relying on client_conn and server_conn having the same IDs */
    if (CONNECTION_does_id_match_skb(&pentry->client_conn->opener.id, skb)) {
        /* Client to proxy */
        result = PACKET_DIRECTION_FROM_CLIENT;
    } else if (CONNECTION_does_id_match_skb(&pentry->client_conn->listener.id, skb)) {
        /* Server to proxy */
        result = PACKET_DIRECTION_FROM_SERVER;
    }

l_cleanup:

    return result;
}

static packet_direction_t
entry_compare_packet_local_out(connection_entry_t *entry,
                               const struct sk_buff *skb)
{
    /* Only proxy packets come in the local out */
    printk(KERN_ERR "%s (skb=%s): non-proxy entry has a local-out packet, entry: %s\n",
           __func__, SKB_str(skb), ENTRY_str(entry));
    return PACKET_DIRECTION_MISMATCH;
}

static packet_direction_t
proxy_entry_compare_packet_local_out(proxy_connection_entry_t *entry,
                                     const struct sk_buff *skb)
{
    packet_direction_t result = PACKET_DIRECTION_MISMATCH;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    if ((NULL == entry) || (NULL == skb)) {
        printk(KERN_ERR "%s: got invalid input\n", __func__);
        goto l_cleanup;
    }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);
    printk(KERN_INFO "%s (skb %s): checking...\n", __func__, SKB_str(skb));
    if (proxy_entry_is_to_client(entry, skb)) {
        printk(KERN_INFO "%s: proxy to client\n", __func__);
        /* Proxy to client */
        result = PACKET_DIRECTION_TO_CLIENT;
    } else if (proxy_entry_is_to_server(entry, skb)) {
        printk(KERN_INFO "%s: proxy to server\n", __func__);
        /* Proxy to server */
        result = PACKET_DIRECTION_TO_SERVER;
    } else {
        printk(KERN_INFO "%s: mismatch!\n", __func__);
    }


l_cleanup:

    return result;
}

static bool_t
proxy_entry_is_to_client(proxy_connection_entry_t *pentry,
                         const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    uint32_t local_ip = NET_UTILS_get_local_ip__network_order(skb->dev);
    bool_t is_src_ip_from_localhost = FALSE;
    bool_t is_src_port_match = FALSE;
    bool_t is_dst_ip_match = FALSE;
    bool_t is_dst_port_match = FALSE;

    /* Note: On LOCAL-OUT hook, we get the skb->dev to be NULL so the soruce IP
     *       is not set correctly. We will treat it as zero */
    printk(KERN_INFO "%s (skb=%s): local_ip=0x%.8x\n", __func__, SKB_str(skb), ntohl(local_ip));
    is_src_ip_from_localhost = (ip_header->saddr == local_ip) || (0 == local_ip);
    is_src_port_match = (tcp_header->source == pentry->client_conn->proxy_port);
    is_dst_ip_match = (ip_header->daddr == pentry->client_conn->listener.id.dst_ip);
    is_dst_port_match = (tcp_header->dest == pentry->client_conn->listener.id.dst_port);

    does_match = (is_src_ip_from_localhost &&
                  is_src_port_match &&
                  is_dst_ip_match &&
                  is_dst_port_match) ? TRUE : FALSE;
    printk(KERN_INFO "%s (skb=%s): local_ip=0x%.8x, entry=%s. results: %d %d %d %d -> %d\n",
            __func__, SKB_str(skb), ntohl(local_ip),
            ENTRY_str((connection_entry_t *)pentry),
            is_src_ip_from_localhost, is_src_port_match,
            is_dst_ip_match, is_dst_port_match, does_match);

    return does_match;
}

static bool_t
proxy_entry_is_to_server(proxy_connection_entry_t *pentry,
                         const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    uint32_t local_ip = NET_UTILS_get_local_ip__network_order(skb->dev);
    bool_t is_src_ip_from_localhost = FALSE;
    bool_t is_src_port_match = FALSE;
    bool_t is_src_port_misconfigured = FALSE;
    bool_t is_dst_ip_match = FALSE;
    bool_t is_dst_port_match = FALSE;

    /* Note: On LOCAL-OUT hook, we get the skb->dev to be NULL so the soruce IP
     *       is not set correctly. We will treat it as zero */
    printk(KERN_INFO "%s (skb=%s): local_ip=0x%.8x\n", __func__, SKB_str(skb), ntohl(local_ip));
    is_src_ip_from_localhost = (0 == local_ip);
    is_src_port_misconfigured = ((0 == pentry->server_conn->proxy_port) &&
                                 (TCP_CLOSE == pentry->server_conn->opener.state));
    is_src_port_match = tcp_header->source == pentry->server_conn->proxy_port;
    is_dst_ip_match = (ip_header->daddr == pentry->server_conn->listener.id.src_ip);
    is_dst_port_match = (tcp_header->dest == pentry->server_conn->listener.id.src_port);

    does_match = (is_src_ip_from_localhost &&
                  (is_src_port_match || is_src_port_misconfigured) &&
                  is_dst_ip_match &&
                  is_dst_port_match) ? TRUE : FALSE;
    printk(KERN_INFO "%s (skb=%s): entry %s. (%d && (%d || %d) && %d && %d) --> %d\n", __func__, SKB_str(skb), ENTRY_str((connection_entry_t *)pentry), is_src_ip_from_localhost, is_src_port_misconfigured, is_src_port_match, is_dst_ip_match, is_dst_port_match, does_match);

    return does_match;
}

static void
proxy_entry_pre_routing_hook(proxy_connection_entry_t *entry,
                           struct sk_buff *skb,
                           packet_direction_t cmp_result)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    bool_t was_modified = TRUE;

    printk(KERN_INFO "%s (skb=%s): enter cmp_result %d\n", __func__, SKB_str(skb), cmp_result);
    switch (cmp_result) 
    {
    case PACKET_DIRECTION_FROM_CLIENT:
        ip_header->daddr = NET_UTILS_get_local_ip__network_order(skb->dev);
        if (0 == ip_header->daddr) {
            printk(KERN_ERR "%s (skb=%s): dest addr from clientis 0\n", __func__, SKB_str(skb));
            /* XXX: log? */
        }
        tcp_header->dest = entry->client_conn->proxy_port;
        printk(KERN_INFO "%s: from client: dest to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->daddr), ntohs(tcp_header->dest));
        break;
    case PACKET_DIRECTION_FROM_SERVER:
        ip_header->daddr = NET_UTILS_get_local_ip__network_order(skb->dev);
        if (0 == ip_header->daddr) {
            printk(KERN_ERR "%s (skb=%s): dest addr from server is 0\n", __func__, SKB_str(skb));
            /* XXX: log? */
        }
        tcp_header->dest = entry->server_conn->proxy_port;
        printk(KERN_INFO "%s: from server: dest to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->daddr), ntohs(tcp_header->dest));
        break;
    case PACKET_DIRECTION_MISMATCH:
    default:
        printk(KERN_INFO "%s (skb=%s): was not modified\n", __func__, SKB_str(skb));
        was_modified = FALSE;
        break;
    }

    /* Ignore failure of checksum */
    if (was_modified) {
        (void)NET_UTILS_fix_checksum(skb);
    }
}

static void
proxy_entry_local_out_hook(proxy_connection_entry_t *entry,
                           struct sk_buff *skb,
                           packet_direction_t cmp_result)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    bool_t was_modified = TRUE;

    printk(KERN_INFO "%s (skb=%s): enter cmp_result %d\n", __func__, SKB_str(skb), cmp_result);
    switch (cmp_result) 
    {
    case PACKET_DIRECTION_TO_SERVER:
        printk(KERN_INFO "%s: to server: source 0x%.8x:%d changed to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->saddr), ntohs(tcp_header->source),
                ntohl(entry->client_conn->listener.id.dst_ip),
                ntohs(entry->client_conn->listener.id.dst_port));
        ip_header->saddr = entry->client_conn->listener.id.dst_ip;
        /* Assign proxy port on first time */
        if (0 == entry->server_conn->proxy_port) {
            printk(KERN_INFO "%s: SETTING THE PROXY PORT FIRST TIME =%d\n", __func__, ntohs(tcp_header->source));
            entry->server_conn->proxy_port = tcp_header->source;
        }
        tcp_header->source = entry->client_conn->listener.id.dst_port;
        break;
    case PACKET_DIRECTION_TO_CLIENT:
        printk(KERN_INFO "%s: to client: source 0x%.8x:%d changed to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->saddr), ntohs(tcp_header->source),
                ntohl(entry->client_conn->opener.id.dst_ip),
                ntohs(entry->client_conn->opener.id.dst_port));
        ip_header->saddr = entry->client_conn->opener.id.dst_ip;
        tcp_header->source = entry->client_conn->opener.id.dst_port;
        break;
    case PACKET_DIRECTION_MISMATCH:
    default:
        printk(KERN_INFO "%s (skb=%s): was not modified\n", __func__, SKB_str(skb));
        was_modified = FALSE;
        break;
    }

    /* Ignore failure of checksum */
    if (was_modified) {
        (void)NET_UTILS_fix_checksum(skb);
    }
}

result_t
CONNECTION_ENTRY_create_from_syn(connection_entry_t **entry_out,
                                  const struct sk_buff *skb)
{
    result_t result = E__UNKNOWN;
    connection_entry_t *entry = NULL;
    connection_entry_vtbl_t *vtable = NULL;

    /* 0. Input validation */
    if ((NULL == entry_out) || (NULL == skb)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Determine if proxy */
    /* 1.1. Check by destination port */
    switch (tcp_hdr(skb)->dest)
    {
        case HTTP_PORT_N:
        case FTP_PORT_N:
            vtable = &g_vtable_connection_proxy;
            break;
        default:
            vtable = &g_vtable_connection_direct;
            break;
    }

    /* 2. Allocate entry */
    result = vtable->create(&entry);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 3. Init entry's connection */
    CONNECTION_ENTRY_init_by_skb(entry, skb);

    /* Success */
    *entry_out = entry;

    result = E__SUCCESS;
l_cleanup:

    if (E__SUCCESS != result) {
        if ((NULL != vtable) && (NULL != entry)) {
            CONNECTION_ENTRY_destroy(entry);
        }
    }

    return result;
}

result_t
CONNECTION_ENTRY_create_from_id(connection_entry_t **entry_out,
                                const connection_id_t *id)
{
    result_t result = E__UNKNOWN;
    connection_entry_t *entry = NULL;
    connection_entry_vtbl_t *vtable = NULL;

    /* 0. Input validation */
    if ((NULL == entry_out) || (NULL == id)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Determine if proxy */
    /* 1.1. Check by destination port */
    switch (id->dst_port)
    {
        case HTTP_PORT_N:
        case FTP_PORT_N:
            vtable = &g_vtable_connection_proxy;
            break;
        default:
            vtable = &g_vtable_connection_direct;
            break;
    }

    /* 2. Allocate entry */
    result = vtable->create(&entry);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 3. Init entry's connection */
    CONNECTION_ENTRY_init_by_id(entry, id);

    /* Success */
    *entry_out = entry;

    result = E__SUCCESS;
l_cleanup:

    if (E__SUCCESS != result) {
        if ((NULL != vtable) && (NULL != entry)) {
            CONNECTION_ENTRY_destroy(entry);
        }
    }

    return result;
}

static void
entry_destroy(connection_entry_t *entry)
{
    if (NULL != entry) {
        KFREE_SAFE(entry->conn);
    }

    KFREE_SAFE(entry);
}

static void
proxy_entry_destroy(proxy_connection_entry_t *pentry)
{
    if (NULL != pentry) {
        KFREE_SAFE(pentry->client_conn);
        KFREE_SAFE(pentry->server_conn);
    }

    KFREE_SAFE(pentry);
}


const char *
SINGLE_CONN_str(const single_connection_t *conn)
{
    if (NULL == conn) {
        (void)memset(g_singleconn_string_buff, 0, sizeof(g_singleconn_string_buff));
    } else {
        snprintf(g_singleconn_string_buff, sizeof(g_singleconn_string_buff),
                "0x%.8x:%d->0x%.8x:%d (state %d)",
                ntohl(conn->id.src_ip), ntohs(conn->id.src_port),
                ntohl(conn->id.dst_ip), ntohs(conn->id.dst_port),
                conn->state);
    }
    return g_singleconn_string_buff;
}


const char *
CONN_str(const connection_t *conn)
{
    size_t i = 0;
    if (NULL == conn) {
        (void)memset(g_conn_string_buff, 0, sizeof(g_conn_string_buff));
    } else {
        i += snprintf(g_conn_string_buff, sizeof(g_conn_string_buff),
                "<Opener: %s>",
                SINGLE_CONN_str(&conn->opener));
        i += snprintf(&g_conn_string_buff[i], sizeof(g_conn_string_buff) - i,
                " <Listener: %s>",
                SINGLE_CONN_str(&conn->listener));
    }
    return g_conn_string_buff;
}

const char *
ENTRY_str(const connection_entry_t *ent)
{
    size_t i = 0;
    if (NULL == ent) {
        (void)memset(g_entry_string_buff, 0, sizeof(g_entry_string_buff));
    } else {
        switch (ent->_vtbl->type)
        {
        case CONNECTION_TYPE_DIRECT:
            snprintf(g_entry_string_buff, sizeof(g_entry_string_buff),
                    "Entry: %s",
                    CONN_str(ent->conn));
            break;
        case CONNECTION_TYPE_PROXY:
            i = snprintf(g_entry_string_buff, sizeof(g_entry_string_buff),
                    "Proxy Entry: [Client (prox %d) %s] ",
                    ntohs(((proxy_connection_entry_t *)ent)->client_conn->proxy_port),
                    CONN_str((connection_t *)((proxy_connection_entry_t *)ent)->client_conn)
                    );
            snprintf(&g_entry_string_buff[i], sizeof(g_entry_string_buff) - i,
                    " [Server (prox %d) %s]",
                    ntohs(((proxy_connection_entry_t *)ent)->server_conn->proxy_port),
                    CONN_str((connection_t *)((proxy_connection_entry_t *)ent)->server_conn)
                    );
        break;
        default:
        break;
        }
    }
    return g_entry_string_buff;
}

const char *
SKB_str(const struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    snprintf(g_skb_string_buff, sizeof(g_skb_string_buff),
            "0x%.8x:%d->0x%.8x:%d (S=%d,A=%d,R=%d,F=%d, dev=%s)",
            ntohl(ip_header->saddr), ntohs(tcp_header->source),
            ntohl(ip_header->daddr), ntohs(tcp_header->dest),
            tcp_header->syn, tcp_header->ack,
            tcp_header->rst, tcp_header->fin,
            (NULL == skb->dev) ? "NULL" : skb->dev->name
            );
    return g_skb_string_buff;
}

static size_t
dump_entry(const connection_entry_t *entry,
           uint8_t *buffer,
           size_t buffer_size)
{
    size_t dumped_size = 0;
    const size_t required_size = sizeof(*entry->conn);

    if ((NULL == entry) || (NULL == buffer)) {
        goto l_cleanup;
    }

    if (buffer_size < required_size) {
        goto l_cleanup;
    }

    (void)memcpy(buffer, entry->conn, required_size);
    dumped_size = required_size;

l_cleanup:

    return dumped_size;
}

static size_t
dump_proxy_entry(const proxy_connection_entry_t *pentry,
                 uint8_t *buffer,
                 size_t buffer_size)
{
    size_t dumped_size = 0;
    const size_t required_size = sizeof(*pentry->client_conn_nonproxy) + sizeof(*pentry->server_conn_nonproxy);

    if ((NULL == pentry) || (NULL == buffer)) {
        goto l_cleanup;
    }

    if (buffer_size < required_size) {
        goto l_cleanup;
    }

    (void)memcpy(buffer, pentry->client_conn_nonproxy, sizeof(*pentry->client_conn_nonproxy));
    (void)memcpy(&buffer[sizeof(*pentry->client_conn_nonproxy)], pentry->server_conn_nonproxy, sizeof(*pentry->server_conn_nonproxy));
    dumped_size = required_size;

l_cleanup:

    return dumped_size;
}

static bool_t
entry_get_conns_by_direction(connection_entry_t *entry,
                             packet_direction_t cmp_res,
                             single_connection_t **src_out,
                             single_connection_t **dst_out)
{
    bool_t is_success = TRUE;

    /* printk(KERN_INFO "%s: hello\n", __func__); */
    if ((NULL != src_out) && (NULL != dst_out)) {
        switch (cmp_res)
        {
        case PACKET_DIRECTION_FROM_CLIENT:
            *src_out = &entry->conn->opener;
            *dst_out = &entry->conn->listener;
            break;
        case PACKET_DIRECTION_FROM_SERVER:
            *src_out = &entry->conn->listener;
            *dst_out = &entry->conn->opener;
            break;
        default:
            is_success = FALSE;
            break;
        }
    }

    return is_success;
}

static bool_t
proxy_entry_get_conns_by_direction(proxy_connection_entry_t *entry,
                                   packet_direction_t cmp_res,
                                   single_connection_t **src_out,
                                   single_connection_t **dst_out)
{
    bool_t is_success = TRUE;

    /* printk(KERN_INFO "%s: hello\n", __func__); */
    if ((NULL != src_out) && (NULL != dst_out)) {
        switch (cmp_res)
        {
        case PACKET_DIRECTION_FROM_CLIENT:
            /* printk(KERN_INFO "%s: from client\n", __func__); */
            *src_out = &entry->client_conn->opener;
            *dst_out = &entry->client_conn->listener;
            break;
        case PACKET_DIRECTION_FROM_SERVER:
            /* printk(KERN_INFO "%s: from server\n", __func__); */
            *src_out = &entry->server_conn->listener;
            *dst_out = &entry->server_conn->opener;
            break;
        case PACKET_DIRECTION_TO_CLIENT:
            /* printk(KERN_INFO "%s: to client\n", __func__); */
            *src_out = &entry->client_conn->listener;
            *dst_out = &entry->client_conn->opener;
            break;
        case PACKET_DIRECTION_TO_SERVER:
            /* printk(KERN_INFO "%s: to server\n", __func__); */
            *src_out = &entry->server_conn->opener;
            *dst_out = &entry->server_conn->listener;
            break;
        default:
            printk(KERN_INFO "%s: error!\n", __func__);
            is_success = FALSE;
            break;
        }
    } else {
        is_success = FALSE;
        printk(KERN_INFO "%s: something is BAD\n", __func__);
    }

    return is_success;
}

static bool_t
entry_is_closed(connection_entry_t *entry)
{
    bool_t is_closed = TRUE;
    
    if (NULL != entry) {
        is_closed = CONNECTION_IS_CLOSED(entry->conn);
    }

    return is_closed;
}

static bool_t
proxy_entry_is_closed(proxy_connection_entry_t *pentry)
{
    bool_t is_closed = TRUE;
    
    if (NULL != pentry) {
        is_closed = (CONNECTION_IS_CLOSED(pentry->server_conn) &&
                     CONNECTION_IS_CLOSED(pentry->client_conn));
    }

    return is_closed;
}

