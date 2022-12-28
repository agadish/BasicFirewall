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

#include "fw.h"
#include "fw_log.h"
#include "common.h"

#include "connection_table.h"


/*   M A C R O S   */


/*    T Y P E D E F S   */
typedef struct connection_table_entry_node_s {
    struct klist_node node;
    connection_table_entry_t entry;
} connection_table_entry_node_t;

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
                  connection_table_entry_t *entry,
                  connection_table_entry_t *ientry);

static connection_table_entry_t *
search_entry(const connection_table_t *table, const struct sk_buff *skb);

static connection_table_entry_t *
search_entry_by_id(const connection_table_t *table, const connection_id_t *id);

static connection_table_entry_t *
search_inverse_entry(const connection_table_t *table, const connection_table_entry_t *entry);

static void
get_skb_id(const struct sk_buff *skb, connection_id_t * id_out);

static void
discard_connection(connection_table_t *table,
                   connection_table_entry_t *entry,
                   connection_table_entry_t *ientry);


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

bool_t
CONNECTION_TABLE_dump_data(const connection_table_t *table,
                     uint8_t *buffer,
                     size_t *buffer_size_inout)
{
    bool_t result = FALSE;
    struct klist_iter list_iter = {0};
    const connection_table_entry_node_t *node = NULL;
    size_t remaining_length = 0;
    size_t current_index = 0;

    if ((NULL == table) || (NULL == buffer) || (NULL == buffer_size_inout)) {
        goto l_cleanup;
    }
    
    remaining_length = *buffer_size_inout;

    /* XXX: Must discard the const, but not modifying it */
    klist_iter_init((struct klist *)&table->list, &list_iter);

    printk(KERN_INFO "%s: enter, buffer size %lu\n", __func__, (unsigned long)remaining_length);
    while (remaining_length > sizeof(node->entry)) {
        /* 1. Get next chunk  */
        node = (connection_table_entry_node_t *)klist_next(&list_iter); 
        printk(KERN_INFO "%s: node scanned 0x%.8x\n", __func__, (uint32_t)node);
        /* 2. Last chunk? break */
        if (NULL == node) {
            break;
        }

        printk(KERN_INFO "%s: copying an entry 0x%.8x:0x%.4x -> 0x%.8x->0x%.4x\n", __func__, node->entry.id.src_ip, node->entry.id.src_port, node->entry.id.dst_ip, node->entry.id.dst_port);
        (void)memcpy(&buffer[current_index], &node->entry, sizeof(node->entry));
        current_index += sizeof(node->entry);
        remaining_length -= sizeof(node->entry);
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
                  connection_table_entry_t *entry,
                  connection_table_entry_t *ientry)
{
    bool_t is_legal_traffic = TRUE;

    struct tcphdr *tcp_header = tcp_hdr(skb);

    /* 1. Check RST */
    if (tcp_header->rst) {
        discard_connection(table, entry, ientry);
        goto l_cleanup;
    }

    /* printk(KERN_INFO "%s: hello\n", __func__); */
    /* 2. Handle TCP state machine */
    printk(KERN_INFO "%s: state %d\n", __func__, entry->state);
    switch (entry->state)
    {
    case TCP_ESTABLISHED:
        /* SYN is illegal, FIN is legal (and closes), everything else is legal */
        if (tcp_header->fin) {
            /* printk(KERN_INFO "%s: state %d got fin\n", __func__, entry->state); */
            entry->state = TCP_FIN_WAIT1;
            ientry->state = TCP_CLOSE_WAIT;
        } else if (tcp_header->syn) {
            /* Detect invalid traffic */
            printk(KERN_INFO "%s: state %d illegal traffic with syn\n", __func__, entry->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        } else {
            /* Default: action remains NF_ACCEPT */
        } 
        break;
    case TCP_SYN_SENT:
        /* Allowed only ACK */
        if (tcp_header->fin || (!tcp_header->ack)) {
            printk(KERN_INFO "%s: state %d illegal traffic with FIN-ACK\n", __func__, entry->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        } else if (tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got ack\n", __func__, entry->state); */
            entry->state = TCP_ESTABLISHED;
            ientry->state = TCP_ESTABLISHED;
        }
        break;
    case TCP_SYN_RECV:
        /* Nothing should be sent after SYN+ACK - drop the connection.
         * Note: it might be accepted later and its not our concern */
        if (tcp_header->syn && tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got synack\n", __func__, entry->state); */
            entry->state = TCP_ESTABLISHED;
            ientry->state = TCP_ESTABLISHED;
        } else if (tcp_header->fin) {
            /* printk(KERN_INFO "%s: state %d got fin\n", __func__, entry->state); */
            entry->state = TCP_CLOSE_WAIT;
            ientry->state = TCP_FIN_WAIT1;
        } else {
            printk(KERN_INFO "%s: state %d got illegal traffic\n", __func__, entry->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        }
        break;
    case TCP_FIN_WAIT1:
        if (tcp_header->fin) {
            if (tcp_header->ack) {
                /* printk(KERN_INFO "%s: state %d got finack\n", __func__, entry->state); */
                entry->state = TCP_TIME_WAIT;
                ientry->state = TCP_CLOSING;
            } else {
                /* printk(KERN_INFO "%s: state %d got fin\n", __func__, entry->state); */
                entry->state = TCP_CLOSING;
                ientry->state = TCP_TIME_WAIT;
            }
        } else if (tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got ack\n", __func__, entry->state); */
            entry->state = TCP_FIN_WAIT2;
            ientry->state = TCP_CLOSE_WAIT;
        }
        break;
    case TCP_FIN_WAIT2:
        if (tcp_header->fin) {
            /* printk(KERN_INFO "%s: state %d got fin\n", __func__, entry->state); */
            entry->state = TCP_TIME_WAIT;
            ientry->state = TCP_CLOSING;
        }
        break;
    case TCP_CLOSING:
        if (tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got ack\n", __func__, entry->state); */
            entry->state = TCP_TIME_WAIT;
            ientry->state = TCP_FIN_WAIT2;
        }
        break;
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
        /* printk(KERN_INFO "%s: state %d discarding\n", __func__, entry->state); */
        discard_connection(table, entry, ientry);
        break;
    case TCP_CLOSE_WAIT:
        if (tcp_header->ack) {
            /* printk(KERN_INFO "%s: state %d got ack\n", __func__, entry->state); */
            entry->state = TCP_LAST_ACK;
            ientry->state = TCP_TIME_WAIT;
        }
        break;
    default:
        printk(KERN_INFO "%s: state %d UNKNOWN! discarding\n", __func__, entry->state);
        is_legal_traffic = FALSE;
        goto l_cleanup;
    }

    /* 3. If traffic was illegal - immediately drop it */

l_cleanup:
    if (!is_legal_traffic) {
        discard_connection(table, entry, ientry);
    }

    return is_legal_traffic;
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

    ientry = search_inverse_entry(table, entry);
    if (NULL == entry) {
        printk(KERN_WARNING "%s: Found an entry in the connection table without its inverse!" \
            " src_ip=0x%.8x dst_ip=0x%.8x src_port=0x%.4x dst_port=0x%.4x\n",
            __func__, entry->id.src_ip, entry->id.dst_ip, entry->id.src_port, entry->id.dst_port);
        goto l_cleanup;
    }

    printk(KERN_INFO "%s: entry=0x%.8x, ientry=0x%.8x\n", __func__, (uint32_t)entry, (uint32_t)ientry);
    was_handled = TRUE;
    is_legal_traffic = tcp_machine_state(table, skb, entry, ientry);
    if (is_legal_traffic) {
        *action_out = NF_ACCEPT;
        /* TODO: Don't log */
        *reason_out = 0;
    } if (!is_legal_traffic) {
        *action_out = NF_DROP;
        *reason_out = REASON_ILLEGAL_VALUE;
    }

l_cleanup:

    return was_handled;
}

result_t
CONNECTION_TABLE_handle_accepted_syn(connection_table_t *table,
                                     const struct sk_buff *skb)
{
    result_t result = E__UNKNOWN;
    connection_table_entry_node_t *original_entry_node = NULL;
    connection_table_entry_node_t *inverse_entry_node = NULL;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = NULL;

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
    original_entry_node = (connection_table_entry_node_t *)kmalloc(sizeof(*original_entry_node), GFP_KERNEL);
    if (NULL == original_entry_node) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    inverse_entry_node = (connection_table_entry_node_t *)kmalloc(sizeof(*inverse_entry_node), GFP_KERNEL);
    if (NULL == inverse_entry_node) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    /* 2. Fill entries */
    original_entry_node->entry.id.src_ip = ip_header->saddr;
    inverse_entry_node->entry.id.dst_ip = ip_header->saddr;

    original_entry_node->entry.id.dst_ip = ip_header->daddr;
    inverse_entry_node->entry.id.src_ip = ip_header->daddr;

    original_entry_node->entry.id.src_port = tcp_header->source;
    inverse_entry_node->entry.id.dst_port = tcp_header->source;

    original_entry_node->entry.id.dst_port = tcp_header->dest;
    inverse_entry_node->entry.id.src_port = tcp_header->dest;;

    original_entry_node->entry.state = TCP_SYN_SENT;
    inverse_entry_node->entry.state = TCP_SYN_RECV;

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
    connection_table_entry_node_t *node = NULL;
    struct klist_iter list_iter = {0};

    /* XXX: Must discard the const, but not modifying it */
    klist_iter_init((struct klist *)&table->list, &list_iter);

    printk(KERN_INFO "%s: searching id 0x%.8x:0x%.4x -> 0x%.8x:0x%.4x\n", __func__, id->src_ip, id->src_port, id->dst_ip, id->dst_port);
    while (TRUE) {
        /* 1. Get next chunk  */
        node = (connection_table_entry_node_t *)klist_next(&list_iter); 
        /* printk(KERN_INFO "%s: node 0x%.8x\n", __func__, (uint32_t)node); */
        /* 2. Last chunk? break */
        if (NULL == node) {
            break;
        }

        /* 3. Check if matches */
        if (0 == memcmp(&node->entry.id, id, sizeof(*id))) {
            /* Found */
            result = &node->entry;
            /* printk(KERN_INFO "%s: found id 0x%8x:0x%.4x -> 0x%.8x:0x%.4x ! addr= 0x%.8x\n", __func__, id->src_ip, id->src_port, id->dst_ip, id->dst_port, (uint32_t)result); */
            break;
        }
    }

    klist_iter_exit(&list_iter);
    printk(KERN_INFO "%s: found 0x%.8x\n", __func__, (uint32_t)result);

    return result;
}

static connection_table_entry_t *
search_inverse_entry(const connection_table_t *table, const connection_table_entry_t *entry)
{
    connection_table_entry_t *result = NULL;
    connection_table_entry_node_t *node = NULL;
    struct klist_iter list_iter = {0};
    connection_table_entry_node_t *prev_node = NULL;
    connection_table_entry_node_t *next_node = NULL;
    connection_id_t inverse_id = {
        .src_ip = entry->id.dst_ip,
        .dst_ip = entry->id.src_ip,
        .src_port = entry->id.dst_port,
        .dst_port = entry->id.src_port
    };

    node = container_of(entry, connection_table_entry_node_t, entry);
    klist_iter_init_node((struct klist *)&table->list, &list_iter, &node->node);
    prev_node = (connection_table_entry_node_t *)klist_prev(&list_iter);
    if (NULL != prev_node) {
        printk(KERN_INFO "%s: prev exists 0x%.8x:0x%.4x -> 0x%.8x:0x%.4x\n", __func__, prev_node->entry.id.src_ip,prev_node->entry.id.src_port, prev_node->entry.id.dst_ip, prev_node->entry.id.dst_port);
    } else {
        printk(KERN_INFO "%s: prev of 0x%.8x is NULL\n", __func__, (uint32_t)&node->node);
    }
    next_node = (connection_table_entry_node_t *)klist_next(&list_iter);
    next_node = (connection_table_entry_node_t *)klist_next(&list_iter);
    if (NULL != next_node) {
        printk(KERN_INFO "%s: next exists 0x%.8x:0x%.4x -> 0x%.8x:0x%.4x\n", __func__, next_node->entry.id.src_ip,next_node->entry.id.src_port, next_node->entry.id.dst_ip, next_node->entry.id.dst_ip);
    } else {
        printk(KERN_INFO "%s: next of 0x%.8x is NULL\n", __func__, (uint32_t)&node->node);
    }
    klist_iter_exit(&list_iter);
    if ((NULL != prev_node) && (0 == memcmp(&prev_node->entry.id, &inverse_id, sizeof(inverse_id)))) {
        printk(KERN_INFO "%s: found as prev node!\n", __func__);
        result = &prev_node->entry;
    } else if ((NULL != next_node) && (0 == memcmp(&next_node->entry.id, &inverse_id, sizeof(inverse_id)))) {
        printk(KERN_INFO "%s: found as next node!\n", __func__);
        result = &next_node->entry;
    } else {
        result = search_entry_by_id(table, &inverse_id);
    }

    return result;
}

static void
discard_connection(connection_table_t *table,
                   connection_table_entry_t *entry,
                   connection_table_entry_t *ientry)
{
    connection_table_entry_node_t *entry_node = NULL;
    connection_table_entry_node_t *ientry_node = NULL;
    entry_node = container_of(entry, connection_table_entry_node_t, entry);
    ientry_node = container_of(ientry, connection_table_entry_node_t, entry);

    klist_del(&entry_node->node);
    KFREE_SAFE(entry_node);
    klist_del(&ientry_node->node);
    KFREE_SAFE(ientry_node);
    printk(KERN_INFO "%s: discarded entry and ientry\n", __func__);
}
