/**
 * @file connection_table.c
 * @author Assaf Gadish
 *
 * @brief Rule table chaining and execution
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <net/tcp.h>

#include "fw.h"
#include "fw_log.h"
#include "common.h"

#include "connection_table.h"


/*   M A C R O S   */
#define HTTP_PORT_N (htons(80))
#define HTTP_USER_PORT_N (htons(800))
#define FTP_PORT_N (htons(21))
#define FTP_USER_PORT_N (htons(210))


/*    T Y P E D E F S   */
typedef struct connection_table_entry_s connection_table_entry_t;
typedef void (*entry_init_f)(connection_table_entry_t *entry,
                             connection_table_entry_t *ientry,
                             const struct sk_buff *skb);

typedef void (*packet_handler_f)(connection_t *conn,
                                 connection_t *iconn,
                                 const struct sk_buff *skb);


/*    S T R U C T S   */

struct connection_table_entry_s {
    struct klist_node node;
    packet_handler_f handler;
    connection_t conn;
};

typedef struct proxy_connection_table_entry_s {
    struct klist_node node;
    packet_handler_f handler;
    proxy_connection_t conn;
} proxy_connection_table_entry_t;

struct connection_table_s {
    struct klist list;
};


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief 
 * 
 * @param[in] skb
 *
 * @return TRUE if SYN packet, otherwise FALSE
 */
static bool_t
is_syn_packet(const struct tcphdr *tcp_header);

static bool_t
tcp_machine_state(connection_table_t *table,
                  const struct sk_buff *skb,
                  connection_t *entry,
                  connection_t *ientry);

static connection_table_entry_t *
search_entry(const connection_table_t *table, const struct sk_buff *skb);

static connection_table_entry_t *
search_entry_by_id(const connection_table_t *table, const connection_id_t *id);

static connection_table_entry_t *
search_inverse_entry(const connection_table_t *table, const connection_t *conn);

static void
get_skb_id(const struct sk_buff *skb, connection_id_t * id_out);

static void
discard_connection(connection_table_t *table,
                   connection_t *conn,
                   connection_t *iconn);

static void
entry_init(connection_table_entry_t *entry,
           connection_table_entry_t *ientry,
           const struct sk_buff *skb);

static void
proxy_entry_init(proxy_connection_table_entry_t *entry,
                 proxy_connection_table_entry_t *ientry,
                 const struct sk_buff *skb);

static void
proxy_handle_packet(proxy_connection_t *conn,
                    proxy_connection_t *iconn,
                    struct sk_buff *skb);

static bool_t
fix_checksum(struct sk_buff *skb);

static void
entry_init_by_id(connection_table_entry_t *entry,
                 connection_table_entry_t *ientry,
                 const connection_id_t * id);

static void
proxy_entry_init_by_id(proxy_connection_table_entry_t *entry,
                       proxy_connection_table_entry_t *inetry,
                       const connection_id_t *id);


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
result_t
CONNECTION_TABLE_create(connection_table_t **table_out)
{
    result_t result = E__UNKNOWN;
    connection_table_t *table = NULL;

    /* 0. Input validation */
    if (NULL == table_out) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Allocate */
    table = (connection_table_t *)kmalloc(sizeof(*table), GFP_KERNEL);
    if (NULL == table) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    /* 2. Init */
    klist_init(&table->list, NULL, NULL);

    /* Success */
    *table_out = table;
    table = NULL;
    result = E__SUCCESS;
l_cleanup:

    if (E__SUCCESS != result) {
        KFREE_SAFE(table);
    }

    return result;
}

void
CONNECTION_TABLE_destroy(connection_table_t *table)
{
    KFREE_SAFE(table);
}

static bool_t
is_syn_packet(const struct tcphdr *tcp_header)
{
    bool_t is_syn_packet = FALSE;

    is_syn_packet = (0 == tcp_header->ack) ? TRUE : FALSE;

    return is_syn_packet;
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
proxy_handle_packet(proxy_connection_t *conn,
                    proxy_connection_t *iconn,
                    struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    ip_header->daddr = INADDR_LOOPBACK;
    tcp_header->dest = conn->proxy_port;
    
    /* Ignore failure of checksum */
    (void)fix_checksum(skb);
}

bool_t
CONNECTION_TABLE_dump_data(const connection_table_t *table,
                     uint8_t *buffer,
                     size_t *buffer_size_inout)
{
    bool_t result = FALSE;
    struct klist_iter list_iter = {0};
    const connection_table_entry_t *node = NULL;
    size_t remaining_length = 0;
    size_t current_index = 0;

    if ((NULL == table) || (NULL == buffer) || (NULL == buffer_size_inout)) {
        goto l_cleanup;
    }
    
    remaining_length = *buffer_size_inout;

    /* XXX: Must discard the const, but not modifying it */
    klist_iter_init((struct klist *)&table->list, &list_iter);

    printk(KERN_INFO "%s: enter, buffer size %lu\n", __func__, (unsigned long)remaining_length);
    while (remaining_length > sizeof(node->conn)) {
        /* 1. Get next chunk  */
        node = (connection_table_entry_t *)klist_next(&list_iter); 
        printk(KERN_INFO "%s: node scanned 0x%.8x\n", __func__, (uint32_t)node);
        /* 2. Last chunk? break */
        if (NULL == node) {
            break;
        }

        printk(KERN_INFO "%s: copying an entry 0x%.8x:0x%.4x -> 0x%.8x->0x%.4x\n", __func__, node->conn.id.src_ip, node->conn.id.src_port, node->conn.id.dst_ip, node->conn.id.dst_port);
        (void)memcpy(&buffer[current_index], &node->conn, sizeof(node->conn));
        current_index += sizeof(node->conn);
        remaining_length -= sizeof(node->conn);
    }

    klist_iter_exit(&list_iter);

    *buffer_size_inout = current_index;

    result = TRUE;
l_cleanup:

    return result;
}

static bool_t
tcp_machine_state(connection_table_t *table,
                  const struct sk_buff *skb,
                  connection_t *conn,
                  connection_t *iconn)
{
    bool_t is_legal_traffic = TRUE;

    struct tcphdr *tcp_header = tcp_hdr(skb);

    /* 1. Check RST */
    if (tcp_header->rst) {
        discard_connection(table, conn, iconn);
        goto l_cleanup;
    }

    /* printk(KERN_INFO "%s: hello\n", __func__); */
    /* 2. Handle TCP state machine */
    printk(KERN_INFO "%s: state %d\n", __func__, conn->state);
    switch (conn->state)
    {
    case TCP_CLOSE:
        if (tcp_header->syn) {
            conn->state = TCP_SYN_SENT;
            iconn->state = TCP_SYN_RECV;
        } else {
            is_legal_traffic = FALSE;
            goto l_cleanup;
        }
    case TCP_ESTABLISHED:
        /* SYN is illegal, FIN is legal (and closes), everything else is legal */
        if (tcp_header->fin) {
            /* printk(KERN_INFO "%s: state %d got fin\n", __func__, conn->state); */
            conn->state = TCP_FIN_WAIT1;
            iconn->state = TCP_CLOSE_WAIT;
        } else if (tcp_header->syn) {
            /* Detect invalid traffic */
            printk(KERN_INFO "%s: state %d illegal traffic with syn\n", __func__, conn->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        } else {
            /* Default: action remains NF_ACCEPT */
        } 
        break;
    case TCP_SYN_SENT:
        /* Allowed only ACK */
        if (tcp_header->fin || (!tcp_header->ack)) {
            printk(KERN_INFO "%s: state %d illegal traffic with FIN-ACK\n", __func__, conn->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        } else if (tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got ack\n", __func__, conn->state); */
            conn->state = TCP_ESTABLISHED;
            iconn->state = TCP_ESTABLISHED;
        }
        break;
    case TCP_SYN_RECV:
        /* Nothing should be sent after SYN+ACK - drop the connection.
         * Note: it might be accepted later and its not our concern */
        if (tcp_header->syn && tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got synack\n", __func__, conn->state); */
            conn->state = TCP_ESTABLISHED;
            iconn->state = TCP_ESTABLISHED;
        } else if (tcp_header->fin) {
            /* printk(KERN_INFO "%s: state %d got fin\n", __func__, conn->state); */
            conn->state = TCP_CLOSE_WAIT;
            iconn->state = TCP_FIN_WAIT1;
        } else {
            printk(KERN_INFO "%s: state %d got illegal traffic\n", __func__, conn->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        }
        break;
    case TCP_FIN_WAIT1:
        if (tcp_header->fin) {
            if (tcp_header->ack) {
                /* printk(KERN_INFO "%s: state %d got finack\n", __func__, conn->state); */
                conn->state = TCP_TIME_WAIT;
                iconn->state = TCP_CLOSING;
            } else {
                /* printk(KERN_INFO "%s: state %d got fin\n", __func__, conn->state); */
                conn->state = TCP_CLOSING;
                iconn->state = TCP_TIME_WAIT;
            }
        } else if (tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got ack\n", __func__, conn->state); */
            conn->state = TCP_FIN_WAIT2;
            iconn->state = TCP_CLOSE_WAIT;
        }
        break;
    case TCP_FIN_WAIT2:
        if (tcp_header->fin) {
            /* printk(KERN_INFO "%s: state %d got fin\n", __func__, conn->state); */
            conn->state = TCP_TIME_WAIT;
            iconn->state = TCP_CLOSING;
        }
        break;
    case TCP_CLOSING:
        if (tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got ack\n", __func__, conn->state); */
            conn->state = TCP_TIME_WAIT;
            iconn->state = TCP_FIN_WAIT2;
        }
        break;
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
        /* printk(KERN_INFO "%s: state %d discarding\n", __func__, conn->state); */
        discard_connection(table, conn, iconn);
        break;
    case TCP_CLOSE_WAIT:
        if (tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got ack\n", __func__, conn->state); */
            conn->state = TCP_LAST_ACK;
            iconn->state = TCP_TIME_WAIT;
        }
        break;
    default:
        printk(KERN_INFO "%s: state %d UNKNOWN! discarding\n", __func__, conn->state);
        is_legal_traffic = FALSE;
        goto l_cleanup;
    }

    /* 3. If traffic was illegal - immediately drop it */

l_cleanup:
    if (!is_legal_traffic) {
        discard_connection(table, conn, iconn);
    }

    return is_legal_traffic;
}

bool_t
CONNECTION_TABLE_track_local_out(connection_table_t *table,
                                 const struct sk_buff *skb)
{
    bool_t was_handled = FALSE;
    connection_table_entry_t *entry = NULL;
    connection_table_entry_t *ientry = NULL;
    bool_t is_proxy_connection = FALSE;

    /* 0. Input validation */
    if ((NULL == table) || (NULL == skb)) {
        printk(KERN_WARNING "CONNECTION_TABLE_check got invalid input\n");
        goto l_cleanup;
    }

    /* 1. Check if exists on the table */
    /* Note: For SYN packets it won't match, and the handling will be done here...
     *       Unless, a connection exists for this SYN packet, and it will be handled accordingly */
    entry = search_entry(table, skb);
    if (NULL == entry) {
        printk(KERN_INFO "%s: no entry for 0x%.8x:0x%.4x -> 0x%.8x->0x%.4x\n", __func__, ip_hdr(skb)->saddr, tcp_hdr(skb)->source, ip_hdr(skb)->daddr, tcp_hdr(skb)->dest);
        goto l_cleanup;
    }

    ientry = search_inverse_entry(table, &entry->conn);
    if (NULL == entry) {
        printk(KERN_WARNING "%s: Found an entry in the connection table without its inverse!" \
            " src_ip=0x%.8x dst_ip=0x%.8x src_port=0x%.4x dst_port=0x%.4x\n",
            __func__, entry->conn.id.src_ip, entry->conn.id.dst_ip, entry->conn.id.src_port, entry->conn.id.dst_port);
        goto l_cleanup;
    }

    /* XXX: Hacky way to identify proxy connection, but that's what happens when
     *      we try to do OOP on C */

    is_proxy_connection = (NULL != entry->handler) ? TRUE : FALSE;
    if (is_proxy_connection) {

        /* switch (conn->state) */
        /* { */
        /*     caseswitch (conn->state) */
        /*     { */
        /*         case  */
    }

l_cleanup:

    return was_handled;
}

bool_t
CONNECTION_TABLE_check(connection_table_t *table,
                       const struct sk_buff *skb,
                       __u8 *action_out,
                       reason_t *reason_out)
{
    bool_t was_handled = FALSE;
    bool_t is_legal_traffic = TRUE;
    connection_table_entry_t *entry = NULL;
    connection_table_entry_t *ientry = NULL;

    /* 0. Input validation */
    if ((NULL == table) || (NULL == skb) || (NULL == action_out) || (NULL == reason_out)) {
        printk(KERN_WARNING "CONNECTION_TABLE_check got invalid input\n");
        goto l_cleanup;
    }

    /* 1. Check if exists on the table */
    /* Note: For SYN packets it won't match, and the handling will be done here...
     *       Unless, a connection exists for this SYN packet, and it will be handled accordingly */
    entry = search_entry(table, skb);
    if (NULL == entry) {
        printk(KERN_INFO "%s: no entry for 0x%.8x:0x%.4x -> 0x%.8x->0x%.4x\n", __func__, ip_hdr(skb)->saddr, tcp_hdr(skb)->source, ip_hdr(skb)->daddr, tcp_hdr(skb)->dest);
        goto l_cleanup;
    }

    ientry = search_inverse_entry(table, &entry->conn);
    if (NULL == entry) {
        printk(KERN_WARNING "%s: Found an entry in the connection table without its inverse!" \
            " src_ip=0x%.8x dst_ip=0x%.8x src_port=0x%.4x dst_port=0x%.4x\n",
            __func__, entry->conn.id.src_ip, entry->conn.id.dst_ip, entry->conn.id.src_port, entry->conn.id.dst_port);
        goto l_cleanup;
    }

    printk(KERN_INFO "%s: entry=0x%.8x, ientry=0x%.8x\n", __func__, (uint32_t)entry, (uint32_t)ientry);
    was_handled = TRUE;
    is_legal_traffic = tcp_machine_state(table, skb, &entry->conn, &ientry->conn);
    if (is_legal_traffic) {
        *action_out = NF_ACCEPT;
        /* TODO: Don't log */
        *reason_out = 0;
    } if (!is_legal_traffic) {
        *action_out = NF_DROP;
        *reason_out = REASON_ILLEGAL_VALUE;
    }

    if (NULL != entry) {
        entry->handler(&entry->conn, &ientry->conn, skb);
    }

l_cleanup:

    return was_handled;
}

static void
entry_init(connection_table_entry_t *entry,
           connection_table_entry_t *ientry,
           const struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    entry->conn.id.src_ip = ip_header->saddr;
    ientry->conn.id.dst_ip = ip_header->saddr;

    entry->conn.id.dst_ip = ip_header->daddr;
    ientry->conn.id.src_ip = ip_header->daddr;

    entry->conn.id.src_port = tcp_header->source;
    ientry->conn.id.dst_port = tcp_header->source;

    entry->conn.id.dst_port = tcp_header->dest;
    ientry->conn.id.src_port = tcp_header->dest;;

    entry->conn.state = TCP_CLOSE;
    ientry->conn.state = TCP_CLOSE;
    entry->handler = NULL;
    ientry->handler = NULL;
}

static void
entry_init_by_id(connection_table_entry_t *entry,
                 connection_table_entry_t *ientry,
                 const connection_id_t * id)
{
    /* 1. Init ID's */
    (void)memcpy(&entry->conn.id, id, sizeof(*id));
    ientry->conn.id.dst_ip = entry->conn.id.src_ip;
    ientry->conn.id.src_ip = entry->conn.id.dst_ip;
    ientry->conn.id.dst_port = entry->conn.id.src_port;
    ientry->conn.id.src_port = entry->conn.id.dst_port;

    /* 2. Init states */
    entry->conn.state = TCP_CLOSE;
    ientry->conn.state = TCP_CLOSE;

    /* 2. Init states */
    entry->handler = NULL;
    ientry->handler = NULL;
}

static void
proxy_entry_init(proxy_connection_table_entry_t *entry,
                 proxy_connection_table_entry_t *ientry,
                 const struct sk_buff *skb)
{
    struct tcphdr *tcp_header = tcp_hdr(skb);

    entry_init((connection_table_entry_t *)entry,
               (connection_table_entry_t *)ientry,
               skb);

    switch (tcp_header->dest) 
    {
        case HTTP_PORT_N:
            entry->conn.proxy_port = HTTP_USER_PORT_N;
            ientry->conn.proxy_port = 0;
            break;
        case FTP_PORT_N:
            entry->conn.proxy_port = FTP_USER_PORT_N;
            ientry->conn.proxy_port = 0;
            break;
        default:
            printk(KERN_ERR "%s: got port that is not HTTP/FTP: %d\n", __func__, ntohs(tcp_header->dest));
            break;
    }

    entry->handler = (packet_handler_f)proxy_handle_packet;
    ientry->handler = (packet_handler_f)proxy_handle_packet;
}

static void
proxy_entry_init_by_id(proxy_connection_table_entry_t *entry,
                       proxy_connection_table_entry_t *ientry,
                       const connection_id_t *id)
{
    entry_init_by_id((connection_table_entry_t *)entry,
                     (connection_table_entry_t *)ientry,
                     id);

    switch (id->dst_port) 
    {
        case HTTP_PORT_N:
            entry->conn.proxy_port = HTTP_USER_PORT_N;
            ientry->conn.proxy_port = 0;
            break;
        case FTP_PORT_N:
            entry->conn.proxy_port = FTP_USER_PORT_N;
            ientry->conn.proxy_port = 0;
            break;
        default:
            printk(KERN_ERR "%s: got port that is not HTTP/FTP: %d\n", __func__, ntohs(id->dst_port));
            break;
    }

    /* 2. Init states */
    entry->handler = (packet_handler_f)proxy_handle_packet;
    ientry->handler = (packet_handler_f)proxy_handle_packet;
}

result_t
CONNECTION_TABLE_handle_accepted_syn(connection_table_t *table,
                                     const struct sk_buff *skb)
{
    result_t result = E__UNKNOWN;
    connection_table_entry_t *original_entry_node = NULL;
    connection_table_entry_t *inverse_entry_node = NULL;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = NULL;

    /* Inheritage-hack variables */
    bool_t is_proxy = FALSE;
    size_t allocation_size = 0;
    entry_init_f init_fn = NULL;

    /* 0. Input validation */
    /* 0.1. NULL validation */
    if ((NULL == table) || (NULL == skb)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 0.2. TCP SYN validation */
    if (IPPROTO_TCP != ip_header->protocol) {
        result = E__SUCCESS;
        goto l_cleanup;
    }
    tcp_header = tcp_hdr(skb);
    if (!is_syn_packet(tcp_header)) {
        result = E__SUCCESS;
        goto l_cleanup;
    }

    /* 1. Allocate 2 new entries */
    switch (tcp_header->dest)
    {
        case HTTP_PORT_N:
        case FTP_PORT_N:
            is_proxy = TRUE;
            init_fn = (entry_init_f)proxy_entry_init;
            allocation_size = sizeof(proxy_connection_t);
            break;
        default:
            init_fn = entry_init;
            allocation_size = sizeof(connection_table_entry_t);
            break;
    }

    original_entry_node = (connection_table_entry_t *)kmalloc(allocation_size, GFP_KERNEL);
    if (NULL == original_entry_node) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    inverse_entry_node = (connection_table_entry_t *)kmalloc(allocation_size, GFP_KERNEL);
    if (NULL == inverse_entry_node) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    /* 2. Init entries entries */
    init_fn(original_entry_node, inverse_entry_node, skb);

    if (is_proxy) {
        proxy_connection_t *original_pconn = &((proxy_connection_table_entry_t *)original_entry_node)->conn;
        switch (tcp_header->dest)
        {
            case HTTP_PORT_N:
                original_pconn->proxy_port = HTTP_USER_PORT_N;
                break;
            case FTP_PORT_N:
                original_pconn->proxy_port = FTP_USER_PORT_N;
                break;
            default:
                printk(KERN_ERR "%s: error dest port not found\n", __func__);
                break;
        }
    }

    /* 3. Add entries */
    klist_add_tail(&original_entry_node->node, &table->list);
    klist_add_tail(&inverse_entry_node->node, &table->list);
    printk(KERN_INFO "%s: added entry+reverse entry\n", __func__);

    /* Success */
    result = E__SUCCESS;
l_cleanup:
    if (E__SUCCESS != result) {
        KFREE_SAFE(original_entry_node);
        KFREE_SAFE(inverse_entry_node);
    }

    return result;
}

/* result_t */
/* CONNECTION_TABLE_handle_accepted_syn(connection_table_t *table, */
/*                                      const struct sk_buff *skb) */
/* { */
/*     result_t result = E__UNKNOWN; */
/*     connection_table_entry_t *original_entry_node = NULL; */
/*     connection_table_entry_t *inverse_entry_node = NULL; */
/*     struct iphdr *ip_header = ip_hdr(skb); */
/*     struct tcphdr *tcp_header = NULL; */
/*  */
/*     [> Inheritage-hack variables <] */
/*     bool_t is_proxy = FALSE; */
/*     size_t allocation_size = 0; */
/*     entry_init_f init_fn = NULL; */
/*  */
/*     [> 0. Input validation <] */
/*     [> 0.1. NULL validation <] */
/*     if ((NULL == table) || (NULL == skb)) { */
/*         result = E__NULL_INPUT; */
/*         goto l_cleanup; */
/*     } */
/*  */
/*     [> 0.2. TCP SYN validation <] */
/*     if (IPPROTO_TCP != ip_header->protocol) { */
/*         result = E__SUCCESS; */
/*         goto l_cleanup; */
/*     } */
/*     tcp_header = tcp_hdr(skb); */
/*     if (!is_syn_packet(tcp_header)) { */
/*         result = E__SUCCESS; */
/*         goto l_cleanup; */
/*     } */
/*  */
/*     [> 1. Allocate 2 new entries <] */
/*     switch (tcp_header->dest) */
/*     { */
/*         case HTTP_PORT_N: */
/*         case FTP_PORT_N: */
/*             is_proxy = TRUE; */
/*             init_fn = (entry_init_f)proxy_entry_init; */
/*             allocation_size = sizeof(proxy_connection_t); */
/*             break; */
/*         default: */
/*             init_fn = entry_init; */
/*             allocation_size = sizeof(connection_table_entry_t); */
/*             break; */
/*     } */
/*  */
/*     original_entry_node = (connection_table_entry_t *)kmalloc(allocation_size, GFP_KERNEL); */
/*     if (NULL == original_entry_node) { */
/*         result = E__KMALLOC_ERROR; */
/*         goto l_cleanup; */
/*     } */
/*  */
/*     inverse_entry_node = (connection_table_entry_t *)kmalloc(allocation_size, GFP_KERNEL); */
/*     if (NULL == inverse_entry_node) { */
/*         result = E__KMALLOC_ERROR; */
/*         goto l_cleanup; */
/*     } */
/*  */
/*     [> 2. Init entries entries <] */
/*     init_fn(&original_entry_node->conn, &inverse_entry_node->conn, skb); */
/*  */
/*     if (is_proxy) { */
/*         proxy_connection_t *original_pconn = &((proxy_connection_t *)original_entry_node)->entry; */
/*         switch (tcp_header->dest) */
/*         { */
/*             case HTTP_PORT_N: */
/*                 original_pconn->proxy_port = HTTP_USER_PORT_N; */
/*                 break; */
/*             case FTP_PORT_N: */
/*                 original_pconn->proxy_port = FTP_USER_PORT_N; */
/*                 break; */
/*             default: */
/*                 printk(KERN_ERR "%s: error dest port not found\n", __func__); */
/*                 break; */
/*         } */
/*     } */
/*  */
/*     [> 3. Add entries <] */
/*     klist_add_tail(&original_entry_node->node, &table->list); */
/*     klist_add_tail(&inverse_entry_node->node, &table->list); */
/*     printk(KERN_INFO "%s: added entry+reverse entry\n", __func__); */
/*  */
/*     [> Success <] */
/*     result = E__SUCCESS; */
/* l_cleanup: */
/*     if (E__SUCCESS != result) { */
/*         KFREE_SAFE(original_entry_node); */
/*         KFREE_SAFE(inverse_entry_node); */
/*     } */
/*  */
/*     return result; */
/* } */

static void
get_skb_id(const struct sk_buff *skb, connection_id_t * id_out)
{
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct tcphdr * tcp_header = tcp_hdr(skb);

    id_out->src_ip = ip_header->saddr;
    id_out->dst_ip = ip_header->daddr;
    id_out->src_port = tcp_header->source;
    id_out->dst_port = tcp_header->dest;
}

static connection_table_entry_t *
search_entry(const connection_table_t *table, const struct sk_buff *skb)
{
    connection_id_t id;
    get_skb_id(skb, &id);
    return search_entry_by_id(table, &id);
}

static connection_table_entry_t *
search_entry_by_id(const connection_table_t *table, const connection_id_t *id)
{
    connection_table_entry_t *result = NULL;
    connection_table_entry_t *node = NULL;
    struct klist_iter list_iter = {0};

    /* XXX: Must discard the const, but not modifying it */
    klist_iter_init((struct klist *)&table->list, &list_iter);

    printk(KERN_INFO "%s: searching id 0x%.8x:0x%.4x -> 0x%.8x:0x%.4x\n", __func__, id->src_ip, id->src_port, id->dst_ip, id->dst_port);
    while (TRUE) {
        /* 1. Get next chunk  */
        node = (connection_table_entry_t *)klist_next(&list_iter); 
        /* printk(KERN_INFO "%s: node 0x%.8x\n", __func__, (uint32_t)node); */
        /* 2. Last chunk? break */
        if (NULL == node) {
            break;
        }

        /* 3. Check if matches */
        if (0 == memcmp(&node->conn.id, id, sizeof(*id))) {
            /* Found */
            result = node;
            /* printk(KERN_INFO "%s: found id 0x%8x:0x%.4x -> 0x%.8x:0x%.4x ! addr= 0x%.8x\n", __func__, id->src_ip, id->src_port, id->dst_ip, id->dst_port, (uint32_t)result); */
            break;
        }
    }

    klist_iter_exit(&list_iter);
    printk(KERN_INFO "%s: found 0x%.8x\n", __func__, (uint32_t)result);

    return result;
}

static connection_table_entry_t *
search_inverse_entry(const connection_table_t *table, const connection_t *conn)
{
    connection_table_entry_t *result = NULL;
    connection_table_entry_t *node = NULL;
    struct klist_iter list_iter = {0};
    connection_table_entry_t *prev_node = NULL;
    connection_table_entry_t *next_node = NULL;
    connection_id_t inverse_id = {
        .src_ip = conn->id.dst_ip,
        .dst_ip = conn->id.src_ip,
        .src_port = conn->id.dst_port,
        .dst_port = conn->id.src_port
    };

    node = container_of(conn, connection_table_entry_t, conn);
    klist_iter_init_node((struct klist *)&table->list, &list_iter, &node->node);
    prev_node = (connection_table_entry_t *)klist_prev(&list_iter);
    if (NULL != prev_node) {
        printk(KERN_INFO "%s: prev exists 0x%.8x:0x%.4x -> 0x%.8x:0x%.4x\n", __func__, prev_node->conn.id.src_ip,prev_node->conn.id.src_port, prev_node->conn.id.dst_ip, prev_node->conn.id.dst_port);
    } else {
        printk(KERN_INFO "%s: prev of 0x%.8x is NULL\n", __func__, (uint32_t)&node->node);
    }
    next_node = (connection_table_entry_t *)klist_next(&list_iter);
    next_node = (connection_table_entry_t *)klist_next(&list_iter);
    if (NULL != next_node) {
        printk(KERN_INFO "%s: next exists 0x%.8x:0x%.4x -> 0x%.8x:0x%.4x\n", __func__, next_node->conn.id.src_ip,next_node->conn.id.src_port, next_node->conn.id.dst_ip, next_node->conn.id.dst_ip);
    } else {
        printk(KERN_INFO "%s: next of 0x%.8x is NULL\n", __func__, (uint32_t)&node->node);
    }
    klist_iter_exit(&list_iter);
    if ((NULL != prev_node) && (0 == memcmp(&prev_node->conn.id, &inverse_id, sizeof(inverse_id)))) {
        printk(KERN_INFO "%s: found as prev node!\n", __func__);
        result = prev_node;
    } else if ((NULL != next_node) && (0 == memcmp(&next_node->conn.id, &inverse_id, sizeof(inverse_id)))) {
        printk(KERN_INFO "%s: found as next node!\n", __func__);
        result = next_node;
    } else {
        result = search_entry_by_id(table, &inverse_id);
    }

    return result;
}

static void
discard_connection(connection_table_t *table,
                   connection_t *conn,
                   connection_t *iconn)
{
    connection_table_entry_t *entry = NULL;
    connection_table_entry_t *ientry = NULL;
    entry = container_of(conn, connection_table_entry_t, conn);
    ientry = container_of(iconn, connection_table_entry_t, conn);

    klist_del(&entry->node);
    KFREE_SAFE(entry);
    klist_del(&ientry->node);
    KFREE_SAFE(ientry);
    printk(KERN_INFO "%s: discarded entry and ientry\n", __func__);
}

result_t
CONNECTION_TABLE_assign_proxy(connection_table_t *table,
                              proxy_connection_t *proxy_conn)
{
    result_t result = E__UNKNOWN;
    proxy_connection_table_entry_t *original_entry_node = NULL;
    proxy_connection_table_entry_t *inverse_entry_node = NULL;
    proxy_connection_t *original_pconn = NULL;

    if ((NULL == table) || (NULL == proxy_conn)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    original_entry_node = (proxy_connection_table_entry_t *)kmalloc(
        sizeof(*original_entry_node),
        GFP_KERNEL
    );
    if (NULL == original_entry_node) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    inverse_entry_node = (proxy_connection_table_entry_t *)kmalloc(
        sizeof(*inverse_entry_node),
        GFP_KERNEL
    );
    if (NULL == inverse_entry_node) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    /* 2. Init entries entries */
    proxy_entry_init_by_id(original_entry_node,
                           inverse_entry_node,
                           &proxy_conn->base.id);

    original_pconn = &original_entry_node->conn;
    switch (original_pconn->base.id.dst_port)
    {
        case HTTP_PORT_N:
            original_pconn->proxy_port = HTTP_USER_PORT_N;
            break;
        case FTP_PORT_N:
            original_pconn->proxy_port = FTP_USER_PORT_N;
            break;
        default:
            printk(KERN_ERR "%s: error dest port not found\n", __func__);
            break;
    }

    /* 3. Add entries */
    klist_add_tail(&original_entry_node->node, &table->list);
    klist_add_tail(&inverse_entry_node->node, &table->list);
    printk(KERN_INFO "%s: added entry+reverse entry\n", __func__);


    result = E__SUCCESS;
l_cleanup:
    if (E__SUCCESS != result) {
        KFREE_SAFE(original_entry_node);
        KFREE_SAFE(inverse_entry_node);
    }

    return result;
}
