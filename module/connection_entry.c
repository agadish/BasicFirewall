/**
 * @file connection.c
 * @author Assaf Gadish
 *
 * @brief Connection functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>

#include "common.h"
#include "fw.h"
#include "connection.h"
#include "fw_results.h"


/*   F U N C T I O N S   D E C L A R A T I O N S   */
static void
entry_init_by_skb(connection_entry_t *entry,
                  const struct sk_buff *skb);

static void
proxy_entry_init_by_skb(connection_entry_t *entry,
                        const struct sk_buff *skb);

static void
entry_init_by_id(connection_entry_t *entry,
                 const connection_id_t * id);

static void
connection_id_flip(connection_id_t *dest,
                   const connection_id_t *src);

static void
proxy_entry_init_by_id(connection_entry_t *entry,
                       const connection_id_t *id);

static void
proxy_init_proxy_ports(connection_entry_t *entry,
                       uint16_t port_n);

static void
proxy_entry_packet_hook(connection_entry_t *entry,
                          struct sk_buff *skb);

static uint32_t
get_local_ip(struct net_device *dev);

static entry_cmp_result_t
entry_compare_packet(connection_entry_t *entry,
                     const struct sk_buff *skb);


static entry_cmp_result_t
proxy_entry_compare_packet(connection_entry_t *entry,
                           const struct sk_buff *skb);

static bool_t
does_connection_id_match_skb(connection_id_t *id,
                             const struct sk_buff *skb);

static bool_t
fix_checksum(struct sk_buff *skb);

/**
 * @remark The returned conn must be freed by calling kfree
 */
static result_t
connection_alloc(connection_t **conn_out);

/**
 * @remark The returned proxy_conn must be freed by calling kfree
 */
static result_t
proxy_connection_alloc(proxy_connection_t **proxy_conn_out);



/*   G L O B A L S   */
connection_entry_vtable_t g_vtable_connection_direct = {
    .type = CONNECTION_TYPE_DIRECT,
    .connection_alloc = connection_alloc;
    .init_by_skb = entry_init_by_skb,
    .init_by_id = entry_init_by_inverse,
    .hook = entry_hook,
    .compare = entry_compare_packet
};

connection_entry_vtable_t g_vtable_connection_proxy = {
    .type = CONNECTION_TYPE_PROXY,
    .connection_alloc = (connection_alloc_f)proxy_connection_alloc;
    .init_by_skb = proxy_entry_init_by_skb,
    .init_by_id = proxy_entry_init_by_id,
    .hook = proxy_entry_packet_hook,
    .compare = proxy_entry_compare_packet
};


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
static result_t
connection_alloc(connection_t **conn_out)
{
    result_t result = E__UNKNOWN;
    connection_t *conn = NULL;

    /* 0. Input validation */
    if (NULL == conn_out) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Allocate a new connection*/
    conn = (connection_t *)kmalloc(sizeof(*conn), GPF_KERNEL);
    if (NULL == conn) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }
    (void)memset(conn, 0, sizeof(*conn));

    /* Success */
    *conn_out = conn;

    result = E__SUCCESS;
l_clenaup:
    if (E__SUCCESS != result) {
        KFREE_SAFE(conn);
    }
    
    return result;
}

static result_t
proxy_connection_alloc(proxy_connection_t **proxy_conn_out)
{
    result_t result = E__UNKNOWN;
    proxy_connection_t *proxy_conn = NULL;

    /* 0. Input validation */
    if (NULL == proxy_conn_out) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Allocate a new connection*/
    proxy_conn = (proxy_connection_t *)kmalloc(sizeof(*proxy_conn), GPF_KERNEL);
    if (NULL == proxy_conn) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }
    (void)memset(proxy_conn, 0, sizeof(*proxy_conn));

    /* Success */
    *proxy_conn_out = proxy_conn;

    result = E__SUCCESS;
l_clenaup:
    if (E__SUCCESS != result) {
        KFREE_SAFE(proxy_conn);
    }
    
    return result;
}

static void
entry_init_by_skb(connection_entry_t *entry,
                  const struct sk_buff *skb)
{
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    /* 0. Input validation */
    if ((NULL == entry) || (NULL == skb)) {
        goto l_cleanup;
    }

    /* 1. ID initialization */
    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    entry->client->id.src_ip = ip_header->saddr;
    entry->client->id.dst_ip = ip_header->daddr;
    entry->client->id.src_port = tcp_header->source;
    entry->client->id.dst_port = tcp_header->dest;

    connection_id_flip(&entry->server->id, &entry->client->id);

    /* 2. State initialiation */
    entry->client->state = TCP_CLOSE;
    entry->server->state = TCP_CLOSE;

l_cleanup:
    return;
}

static void
proxy_entry_init_by_skb(connection_entry_t *entry,
                        const struct sk_buff *skb)
{
    /* 0. Input validation */
    if ((NULL == entry) || (NULL == skb)) {
        goto l_cleanup;
    }

    /* 1. Call super function */
    entry_init_by_skb(entry, skb);

    /* 2. Init proxy port */
    proxy_init_proxy_ports(tcp_hdr(skb)->dest

l_cleanup:
    return;
}

static void
connection_id_flip(connection_id_t *result,
                   const connection_id_t *origin)
{
    result->dest_ip = origin->src_ip;
    result->dest_port = origin->src_port;
    result->src_ip = origin->dest_ip;
    result->src_port = origin->dest_port;
}

static bool_t
fix_checksum(struct sk_buff *skb)
{
    bool_t should_be_dropped = FALSE;
    uint16_t tcplen = 0;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    
    /* Fix IP header checksum */
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

    /*
     * From Linux doc here: https://elixir.bootlin.com/linux/v4.15/source/include/linux/skbuff.h#L90
     * CHECKSUM_NONE:
     *
     *   Device did not checksum this packet e.g. due to lack of capabilities.
     *   The packet contains full (though not verified) checksum in packet but
     *   not in skb->csum. Thus, skb->csum is undefined in this case.
     */
    skb->ip_summed = CHECKSUM_NONE;
    skb->csum_valid = 0;

    /* Linearize the skb */
    if (skb_linearize(skb) < 0) {
        should_be_dropped = TRUE;
        goto l_cleanup;
   }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    /* Fix TCP header checksum */
    tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));

l_cleanup:

    return should_be_dropped;
}

static void
entry_init_by_id(connection_entry_t *entry,
                 const connection_id_t * id)
{
    /* 1. Init ID's */
    (void)memcpy(&entry->client->id, id, sizeof(*id));
    connection_id_flip(&entry->server->id, &entry->client->id);

    /* 2. Init states */
    entry->server->state = TCP_CLOSE;
    entry->client->state = TCP_CLOSE;
}

static void
proxy_init_proxy_ports(connection_entry_t *entry,
                       uint16_t port_n)
{
    switch (port_n) 
    {
        case HTTP_PORT_N:
            printk(KERN_INFO "%s (skb=%p): hello port 80\n", __func__, skb);
            entry->client_proxy->proxy_port = HTTP_USER_PORT_N;
            entry->server_proxy->proxy_port = 0; /* Will be set later */
            break;
        case FTP_PORT_N:
            printk(KERN_INFO "%s (skb=%p): hello port 21\n", __func__, skb);
            entry->client_proxy->proxy_port = FTP_USER_PORT_N;
            entry->server_proxy->proxy_port = 0; /* Will be set later */
            break;
        default:
            printk(KERN_ERR "%s (skb=%p): got port that is not HTTP/FTP: %d\n", __func__, skb, ntohs(tcp_header->dest));
            goto l_cleanup;
            break;
    }
}

static void
proxy_entry_init_by_id(connection_entry_t *entry,
                       const connection_id_t *id)
{
    /* 0. Input validation */
    if ((NULL == entry) || (NULL == id)) {
        goto l_cleanup;
    }

    /* 1. Call super function */
    entry_init_by_id(entry, id);

    /* 2. Init proxy port */
    proxy_init_proxy_ports(tcp_hdr(skb)->dest

l_cleanup:
    return;
}

static uint32_t
get_local_ip(struct net_device *dev)
{
    uint32_t result = INADDR_LOOPBACK;
    struct in_device *in_dev = NULL;
    struct in_ifaddr *ifa = NULL;

    in_dev = (struct in_device *)dev->ip_ptr;
    if (NULL != in_dev) {
        ifa = in_dev->ifa_list;
        if (NULL != ifa) {
            result = ifa->ifa_address;
        } else {
            printk(KERN_ERR "%s: device doesn't have an IP\n", __func__);
        }
    } else {
        printk(KERN_ERR "%s: device doesn't have an IP\n", __func__);
    }


    return result;
}

static entry_cmp_result_t
entry_compare_packet(connection_entry_t *entry,
                     const struct sk_buff *skb)
{
    entry_cmp_result_t result = ENTRY_CMP_RESULT_INVALID;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    if ((NULL == entry) || (NULL == skb)) {
        printk(KERN_ERR "%s: got invalid input\n", __func__);
        goto l_cleanup;
    }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);
    if (does_connection_id_match_skb(&entry->client->id, skb)) {
        /* Client to proxy */
        result = ENTRY_CMP_FROM_CLIENT;
    } else if (does_connection_id_match_skb(&entry->server->id, skb)) {
        /* Server to proxy */
        result = ENTRY_CMP_FROM_SERVER;
    }

l_cleanup:

    return result;
}

static entry_cmp_result_t
proxy_entry_compare_packet(connection_entry_t *entry,
                           const struct sk_buff *skb)
{
    entry_cmp_result_t result = ENTRY_CMP_RESULT_INVALID;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    if ((NULL == entry) || (NULL == skb)) {
        printk(KERN_ERR "%s: got invalid input\n", __func__);
        goto l_cleanup;
    }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);
    if (does_connection_id_match_skb(&entry->client->id, skb)) {
        /* Client to proxy */
        result = ENTRY_CMP_FROM_CLIENT;
    } else if (does_connection_id_match_skb(&entry->server->id, skb)) {
        /* Server to proxy */
        result = ENTRY_CMP_FROM_SERVER;
    } else if (does_proxy_connection_match_skb(entry->client_proxy, skb)) {
        /* Proxy to client */
        result = ENTRY_CMP_TO_CLIENT;
    } else if (does_proxy_connection_match_skb(entry->server_proxy, skb)) {
        /* Proxy to server */
        result = ENTRY_CMP_TO_SERVER;
    }


l_cleanup:

    return result;
}

static bool_t
does_connection_id_match_skb(connection_id_t *id,
                             const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    if ((ip_header->saddr == id->src_ip) &&
        (tcp_header->source == id->src_port) &&
        (ip_header->daddr == id->dst_ip) &&
        (tcp_header->dest == id->dst_port))
    {
        does_match = TRUE;
    }

    return does_match;
}

static bool_t
does_proxy_connection_match_skb(proxy_connection_t *proxy_conn,
                                const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    uint32_t local_ip = get_local_ip(skb->dev);

    if ((ip_header->saddr == local_ip) &&
        ((0 == proxy_conn->proxy_port) || (tcp_header->source == proxy_conn->proxy_port)) &&
        (ip_header->daddr == proxy_conn->base.id->dst_ip) &&
        (tcp_header->dest == proxy_conn->base.id->dst_port))
    {
        does_match = TRUE;
    }

    return does_match;
}

static void
entry_packet_hook(connection_entry_t *entry,
                          struct sk_buff *skb)
{
    UNUSED_PARAM(entry);
    UNUSED_PARAM(skb);

    /* No processing is required */
}

static void
proxy_entry_packet_hook(connection_entry_t *entry,
                          struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    entry_cmp_result_t cmp_result = ENTRY_CMP_MISMATCH;
    bool_t was_modified = TRUE;

    entry_cmp_result = CONNECTION_ENTRY_compare(entry, skb);
    switch (entry_cmp_result) 
    {
    case ENTRY_CMP_FROM_CLIENT:
        ip_header->daddr = get_local_ip(skb->dev);
        if (INADDR_LOOPBACK == ip_header->daddr) {
            printk(KERN_ERR "%s (skb=%p): dest addr from clientis INADDR_LOOPBACK\n", __func__, skb);
            /* XXX: log? */
        }
        tcp_header->dest = entry->client_proxy->proxy_port;
        printk(KERN_INFO "%s: from client: dest to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->daddr), ntohs(tcp_header->dest));
        break;
    case ENTRY_CMP_FROM_SERVER:
        ip_header->daddr = get_local_ip(skb->dev);
        if (INADDR_LOOPBACK == ip_header->daddr) {
            printk(KERN_ERR "%s (skb=%p): dest addr from server is INADDR_LOOPBACK\n", __func__, skb);
            /* XXX: log? */
        }
        tcp_header->dest = entry->server_proxy->proxy_port;
        printk(KERN_INFO "%s: from server: dest to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->daddr), ntohs(tcp_header->dest));
        break;
    case ENTRY_CMP_TO_SERVER:
        printk(KERN_INFO "%s: source 0x%.8x:%d changed to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->saddr), ntohs(tcp_header->source),
                ntohl(entry->server_proxy->base.id.dst_ip),
                ntohs(entry->server_proxy->base.id.dst_port));
        ip_header->saddr = entry->server_proxy->base.id.dst_ip;
        /* Assign proxy port on first time */
        if (0 == entry->server_proxy->proxy_port) {
            entry->server_proxy->proxy_port = tcp_header->source;
        }
        tcp_header->source = entry->server_proxy->base.id.dst_port;
        break;
    case ENTRY_CMP_TO_CLIENT:
        printk(KERN_INFO "%s: source 0x%.8x:%d changed to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->saddr), ntohs(tcp_header->source),
                ntohl(entry->client_proxy->base.id.dst_ip),
                ntohs(entry->client_proxy->base.id.dst_port));
        ip_header->saddr = entry->client_proxy->base.id.dst_ip;
        tcp_header->source = entry->client_proxy->base.id.dst_port;
        break;
    case ENTRY_CMP_MISMATCH:
    default:
        was_modified = FALSE;
        break;

    }

    /* Ignore failure of checksum */
    if (was_modified) {
        (void)fix_checksum(skb);
    }
}

result_t
CONNECTION_ENTRY_create_from_syn(connection_entry_t **entry_out,
                                  const struct sk_buff *skb)
{
    result_t result = E__UNKNOWN;
    connection_entry_t *entry = NULL;
    bool_t is_proxy = FALSE;
    const connection_entry_vtable_t *vtable = NULL;

    /* 0. Input validation */
    if ((NULL == entry_out) || (NULL == skb)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Determine if proxy */
    /* 1.1. Check by destination port */
    switch (tcp_header->dest)
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
    entry = (connection_entry_t *)kmalloc(sizeof(*entry), GPF_KERNEL);
    if (NULL == entry) {
        printk(KERN_ERR "%s: can't allocate entry\n", __func__);
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }
    (void)memset(entry, 0, sizeof(*entry));

    /* 3. Assign vtable */
    entry->_vtbl = vtable;

    /* 4. Create connections */
    /* 4.1. Client connection */
    result = CONNECTION_ENTRY_connection_alloc(&entry->client);
    if (E__SUCCESS != result) {
        printk(KERN_ERR "%s: can't allocate client connection\n", __func__);
        goto l_cleanup;
    }
    /* 4.2. Server connection */
    result = CONNECTION_ENTRY_connection_alloc(&server->client);
    if (E__SUCCESS != result) {
        printk(KERN_ERR "%s: can't allocate client connection\n", __func__);
        goto l_cleanup;
    }

    /* 5. Init entry's connection */
    CONNECTION_ENTRY_init_by_skb(entry);

    /* Success */
    *entry_out = entry;

    result = E__SUCCESS;
l_cleanup:

    if (E__SUCCESS != result) {
        CONNECTION_ENTRY_destroy(entry);
    }

    return result;
}

void
CONNECTION_ENTRY_destroy(connection_entry_t *entry)
{
    if (NULL != entry) {
        FREE_SAFE(entry->client);
        FREE_SAFE(entry->server);
    }

    FREE_SAFE(entry);
}
