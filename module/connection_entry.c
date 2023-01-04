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
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>

#include "common.h"
#include "fw.h"
#include "connection_entry.h"
#include "fw_results.h"


/*   F U N C T I O N S   D E C L A R A T I O N S   */
static void
entry_init_by_skb(connection_entry_t *entry,
                  const struct sk_buff *skb);

static void
proxy_entry_init_by_skb(proxy_connection_entry_t *entry,
                        const struct sk_buff *skb);

static void
connection_id_flip(connection_id_t *dest,
                   const connection_id_t *src);

static void
proxy_init_proxy_ports(proxy_connection_entry_t *entry,
                       uint16_t port_n);

static void
entry_packet_hook(connection_entry_t *entry,
                          struct sk_buff *skb);

static void
proxy_entry_packet_hook(proxy_connection_entry_t *entry,
                          struct sk_buff *skb);

static uint32_t
get_local_ip__network_order(struct net_device *dev);

static entry_cmp_result_t
entry_compare_packet(connection_entry_t *entry,
                     const struct sk_buff *skb);


static entry_cmp_result_t
proxy_entry_compare_packet(proxy_connection_entry_t *entry,
                           const struct sk_buff *skb);

static bool_t
does_connection_id_match_skb(connection_id_t *id,
                             const struct sk_buff *skb);

static bool_t
fix_checksum(struct sk_buff *skb);

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
proxy_entry_is_from_client(proxy_connection_entry_t *pentry,
                           const struct sk_buff *skb);

static bool_t
proxy_entry_is_from_server(proxy_connection_entry_t *pentry,
                           const struct sk_buff *skb);

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
entry_get_conn_by_cmp(connection_entry_t *entry,
                      entry_cmp_result_t cmp_res,
                      single_connection_t **src_out,
                      single_connection_t **dst_out);

static bool_t
proxy_entry_get_conn_by_cmp(proxy_connection_entry_t *entry,
                      entry_cmp_result_t cmp_res,
                      single_connection_t **src_out,
                      single_connection_t **dst_out);

static void
conn_init_by_skb(connection_t *conn,
                 const struct sk_buff *skb);


/* static void */
/* conn_init_by_inverse_conn(connection_t *conn, */
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
    .init_by_skb = entry_init_by_skb,
    .hook = entry_packet_hook,
    .dump = dump_entry,
    .get_conn_by_cmp = entry_get_conn_by_cmp,
    .compare = entry_compare_packet
};

connection_entry_vtbl_t g_vtable_connection_proxy = {
    .type = CONNECTION_TYPE_PROXY,
    .create = (entry_create_f)proxy_entry_create,
    .destroy = (entry_destroy_f)proxy_entry_destroy,
    .init_by_skb = (entry_init_by_skb_f)proxy_entry_init_by_skb,
    .hook = (entry_hook_f)proxy_entry_packet_hook,
    .dump = (dump_entry_f)dump_proxy_entry,
    .get_conn_by_cmp = (get_conn_by_cmp_f)proxy_entry_get_conn_by_cmp,
    .compare = (entry_compare_f)proxy_entry_compare_packet
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
conn_init_by_skb(connection_t *conn,
                 const struct sk_buff *skb)
{
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    /* 0. Input validation */
    if ((NULL == conn) || (NULL == skb)) {
        goto l_cleanup;
    }

    /* 1. ID initialization */
    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    conn->opener.id.src_ip = ip_header->saddr;
    conn->opener.id.dst_ip = ip_header->daddr;
    conn->opener.id.src_port = tcp_header->source;
    conn->opener.id.dst_port = tcp_header->dest;

    connection_id_flip(&conn->listener.id, &conn->opener.id);
    /* printk(KERN_INFO "%s: flipped. conn=%s\n", __func__, CONN_str(conn)); */

    /* 2. State initialiation */
    conn->opener.state = TCP_CLOSE;
    conn->listener.state = TCP_CLOSE;

l_cleanup:
    return;
}

/* static void */
/* conn_init_by_inverse_conn(connection_t *conn, */
/*                           const connection_t *inverse_conn) */
/* { */
/*     (void)memcpy(&conn->opener, &inverse_conn->listener, sizeof(conn->opener)); */
/*     (void)memcpy(&conn->listener, &inverse_conn->opener, sizeof(conn->opener)); */
/*     printk(KERN_INFO "%s: init by inverse conn\norig: %s\n", __func__, CONN_str(inverse_conn)); */
/*     printk(KERN_INFO "inverse: %s\n", CONN_str(inverse_conn)); */
/* } */

static void
entry_init_by_skb(connection_entry_t *entry,
                  const struct sk_buff *skb)
{
    conn_init_by_skb(entry->conn, skb);
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
    conn_init_by_skb((connection_t *)entry->client_conn, skb);
    /* printk(KERN_INFO "%s: client_conn= %s\n", __func__, CONN_str((connection_t *)entry->client_conn)); */
    conn_init_by_skb((connection_t *)entry->server_conn, skb);
    /* conn_init_by_inverse_conn((connection_t *)entry->server_conn, */
    /*                           (connection_t *)entry->client_conn); */

    /* 2. Proxy ports */
    proxy_init_proxy_ports(entry, tcp_header->dest);

l_cleanup:
    return;
}

static void
connection_id_flip(connection_id_t *result,
                   const connection_id_t *origin)
{
    result->dst_ip = origin->src_ip;
    result->dst_port = origin->src_port;
    result->src_ip = origin->dst_ip;
    result->src_port = origin->dst_port;
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
proxy_init_proxy_ports(proxy_connection_entry_t *entry,
                       uint16_t port_n)
{
    switch (port_n) 
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
            printk(KERN_ERR "%s: got port that is not HTTP/FTP: %d\n", __func__, ntohs(port_n));
            break;
    }
}

static uint32_t
get_local_ip__network_order(struct net_device *dev)
{
    uint32_t result = 0;
    struct in_device *in_dev = NULL;
    struct in_ifaddr *ifa = NULL;

    if (NULL == dev) {
        printk(KERN_ERR "%s: got NULL - returning 0\n", __func__);
        result = 0;
        goto l_cleanup;
    }

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


l_cleanup:

    return result;
}

static entry_cmp_result_t
entry_compare_packet(connection_entry_t *entry,
                     const struct sk_buff *skb)
{
    entry_cmp_result_t result = ENTRY_CMP_MISMATCH;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    if ((NULL == entry) || (NULL == skb)) {
        printk(KERN_ERR "%s: got invalid input\n", __func__);
        goto l_cleanup;
    }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);
    if (does_connection_id_match_skb(&entry->conn->opener.id, skb)) {
        /* Client to proxy */
        result = ENTRY_CMP_FROM_CLIENT;
    } else if (does_connection_id_match_skb(&entry->conn->listener.id, skb)) {
        /* Server to proxy */
        result = ENTRY_CMP_FROM_SERVER;
    }

l_cleanup:

    return result;
}

static entry_cmp_result_t
proxy_entry_compare_packet(proxy_connection_entry_t *entry,
                           const struct sk_buff *skb)
{
    entry_cmp_result_t result = ENTRY_CMP_MISMATCH;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    if ((NULL == entry) || (NULL == skb)) {
        printk(KERN_ERR "%s: got invalid input\n", __func__);
        goto l_cleanup;
    }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);
    printk(KERN_INFO "%s (skb %s): checking...\n", __func__, SKB_str(skb));
    if (proxy_entry_is_from_client(entry, skb)) {
        printk(KERN_INFO "%s: client to proxy\n", __func__);
        /* Client to proxy */
        result = ENTRY_CMP_FROM_CLIENT;
    } else if (proxy_entry_is_from_server(entry, skb)) {
        printk(KERN_INFO "%s: server to proxy\n", __func__);
        /* Server to proxy */
        result = ENTRY_CMP_FROM_SERVER;
    } else if (proxy_entry_is_to_client(entry, skb)) {
        printk(KERN_INFO "%s: proxy to client\n", __func__);
        /* Proxy to client */
        result = ENTRY_CMP_TO_CLIENT;
    } else if (proxy_entry_is_to_server(entry, skb)) {
        printk(KERN_INFO "%s: proxy to server\n", __func__);
        /* Proxy to server */
        result = ENTRY_CMP_TO_SERVER;
    } else {
        printk(KERN_INFO "%s: mismatch!\n", __func__);
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
proxy_entry_is_from_client(proxy_connection_entry_t *pentry,
                           const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    bool_t is_src_ok = FALSE;
    bool_t is_dst_ok = FALSE;

    /* Note: On LOCAL-OUT hook, we get the skb->dev to be NULL so the soruce IP
     *       is not set correctly. We will treat it as zero */
    if (NULL == pentry->client_conn || NULL == pentry->server_conn) {
        printk(KERN_INFO "%s: CRAZY BUG\n", __func__);
        return FALSE;
    }
    is_src_ok = ((ip_header->saddr == pentry->client_conn->opener.id.src_ip) &&
                 (tcp_header->source == pentry->client_conn->opener.id.src_port));
    is_dst_ok = ((ip_header->daddr == pentry->server_conn->listener.id.src_ip) &&
                 (tcp_header->dest == pentry->server_conn->listener.id.src_port));

    does_match = is_src_ok && is_dst_ok;
    printk(KERN_INFO "%s (skb=%s): res %d %d -> %d, entry %s\n", __func__, SKB_str(skb), is_src_ok, is_dst_ok, does_match, ENTRY_str((connection_entry_t *)pentry));

    return does_match;
}
    
static bool_t
proxy_entry_is_from_server(proxy_connection_entry_t *pentry,
                           const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    bool_t is_src_ok = FALSE;
    bool_t is_dst_ok = FALSE;

    /* Note: On LOCAL-OUT hook, we get the skb->dev to be NULL so the soruce IP
     *       is not set correctly. We will treat it as zero */
    is_src_ok = ((ip_header->saddr == pentry->server_conn->listener.id.src_ip) &&
                 (tcp_header->source == pentry->server_conn->listener.id.src_port));
    is_dst_ok = ((ip_header->daddr == pentry->client_conn->opener.id.src_ip) &&
                 (tcp_header->dest == pentry->client_conn->opener.id.src_port));

    does_match = is_src_ok && is_dst_ok;
    printk(KERN_INFO "%s (skb=%s): res %d %d -> %d, entry %s\n", __func__, SKB_str(skb), is_src_ok, is_dst_ok, does_match, ENTRY_str((connection_entry_t *)pentry));

    return does_match;
}

static bool_t
proxy_entry_is_to_client(proxy_connection_entry_t *pentry,
                         const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    uint32_t local_ip = get_local_ip__network_order(skb->dev);
    bool_t is_src_ip_from_localhost = FALSE;
    bool_t is_src_port_match = FALSE;
    bool_t is_dst_ip_match = FALSE;
    bool_t is_dst_port_match = FALSE;

    /* Note: On LOCAL-OUT hook, we get the skb->dev to be NULL so the soruce IP
     *       is not set correctly. We will treat it as zero */
    printk(KERN_INFO "%s (skb=%s): local_ip=0x%.8x\n", __func__, SKB_str(skb), ntohl(local_ip));
    is_src_ip_from_localhost = (0 == local_ip);
    is_src_port_match = tcp_header->source == pentry->client_conn->proxy_port;
    is_dst_ip_match = (ip_header->daddr == pentry->client_conn->listener.id.dst_ip);
    is_dst_port_match = (tcp_header->dest == pentry->client_conn->listener.id.dst_port);

    does_match = (is_src_ip_from_localhost &&
                  is_src_port_match &&
                  is_dst_ip_match &&
                  is_dst_port_match) ? TRUE : FALSE;
    /* printk(KERN_INFO "%s (skb=%s): local_ip=0x%.8x, proxy: proxy_port=%d, 0x%.8x:%d->0x%.8x:%d. results: %d %d %d %d -> %d\n", */
    /*         __func__, SKB_str(skb), ntohl(local_ip), ntohs(proxy_conn->proxy_port), */
    /*         ntohl(proxy_conn->id.src_ip), ntohs(proxy_conn->id.src_port), */
    /*         ntohl(proxy_conn->id.dst_ip), ntohs(proxy_conn->id.dst_port), */
    /*         is_src_ip_from_localhost, is_src_port_match, */
    /*         is_dst_ip_match, is_dst_port_match, does_match); */

    return does_match;
}

static bool_t
proxy_entry_is_to_server(proxy_connection_entry_t *pentry,
                         const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    uint32_t local_ip = get_local_ip__network_order(skb->dev);
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
    is_src_port_match = tcp_header->source == pentry->client_conn->proxy_port;
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
entry_packet_hook(connection_entry_t *entry,
                          struct sk_buff *skb)
{
    UNUSED_ARG(entry);
    UNUSED_ARG(skb);

    /* No processing is required */
}

static void
proxy_entry_packet_hook(proxy_connection_entry_t *entry,
                        struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);
    entry_cmp_result_t cmp_result = ENTRY_CMP_MISMATCH;
    bool_t was_modified = TRUE;

    printk(KERN_INFO "%s (skb=%s): enter\n", __func__, SKB_str(skb));
    cmp_result = CONNECTION_ENTRY_compare(entry, skb);
    switch (cmp_result) 
    {
    case ENTRY_CMP_FROM_CLIENT:
        ip_header->daddr = get_local_ip__network_order(skb->dev);
        if (0 == ip_header->daddr) {
            printk(KERN_ERR "%s (skb=%s): dest addr from clientis 0\n", __func__, SKB_str(skb));
            /* XXX: log? */
        }
        tcp_header->dest = entry->client_conn->proxy_port;
        printk(KERN_INFO "%s: from client: dest to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->daddr), ntohs(tcp_header->dest));
        break;
    case ENTRY_CMP_FROM_SERVER:
        ip_header->daddr = get_local_ip__network_order(skb->dev);
        if (0 == ip_header->daddr) {
            printk(KERN_ERR "%s (skb=%s): dest addr from server is 0\n", __func__, SKB_str(skb));
            /* XXX: log? */
        }
        tcp_header->dest = entry->client_conn->proxy_port;
        printk(KERN_INFO "%s: from server: dest to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->daddr), ntohs(tcp_header->dest));
        break;
    case ENTRY_CMP_TO_SERVER:
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
    case ENTRY_CMP_TO_CLIENT:
        printk(KERN_INFO "%s: to client: source 0x%.8x:%d changed to 0x%.8x:%d\n", __func__,
                ntohl(ip_header->saddr), ntohs(tcp_header->source),
                ntohl(entry->client_conn->opener.id.dst_ip),
                ntohs(entry->client_conn->opener.id.dst_port));
        ip_header->saddr = entry->client_conn->opener.id.dst_ip;
        tcp_header->source = entry->client_conn->opener.id.dst_port;
        break;
    case ENTRY_CMP_MISMATCH:
    default:
        printk(KERN_INFO "%s (skb=%s): was not modified\n", __func__, SKB_str(skb));
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
entry_get_conn_by_cmp(connection_entry_t *entry,
                      entry_cmp_result_t cmp_res,
                      single_connection_t **src_out,
                      single_connection_t **dst_out)
{
    bool_t is_success = TRUE;

    /* printk(KERN_INFO "%s: hello\n", __func__); */
    if ((NULL != src_out) && (NULL != dst_out)) {
        switch (cmp_res)
        {
        case ENTRY_CMP_FROM_CLIENT:
            *src_out = &entry->conn->opener;
            *dst_out = &entry->conn->listener;
            break;
        case ENTRY_CMP_FROM_SERVER:
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
proxy_entry_get_conn_by_cmp(proxy_connection_entry_t *entry,
                      entry_cmp_result_t cmp_res,
                      single_connection_t **src_out,
                      single_connection_t **dst_out)
{
    bool_t is_success = TRUE;

    /* printk(KERN_INFO "%s: hello\n", __func__); */
    if ((NULL != src_out) && (NULL != dst_out)) {
        switch (cmp_res)
        {
        case ENTRY_CMP_FROM_CLIENT:
            /* printk(KERN_INFO "%s: from client\n", __func__); */
            *src_out = &entry->client_conn->opener;
            *dst_out = &entry->client_conn->listener;
            break;
        case ENTRY_CMP_FROM_SERVER:
            /* printk(KERN_INFO "%s: from server\n", __func__); */
            *src_out = &entry->server_conn->listener;
            *dst_out = &entry->server_conn->opener;
            break;
        case ENTRY_CMP_TO_CLIENT:
            /* printk(KERN_INFO "%s: to client\n", __func__); */
            *src_out = &entry->client_conn->listener;
            *dst_out = &entry->client_conn->opener;
            break;
        case ENTRY_CMP_TO_SERVER:
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
