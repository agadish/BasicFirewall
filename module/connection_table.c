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

#include "fw.h"
#include "fw_log.h"
#include "common.h"

#include "connection_entry.h"
#include "connection_table.h"


/*    T Y P E D E F S   */


/*    S T R U C T S   */
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
                  connection_entry_t *entry,
                  entry_cmp_result_t cmp_result);

static entry_cmp_result_t
search_entry(struct klist *entries_list,
             const struct sk_buff *skb,
             connection_entry_t **entry_out);

static void
remove_entry(connection_entry_t *entry);


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
    struct klist_iter list_iter = {0};
    connection_entry_t *current_entry = NULL;
    connection_entry_t *next_entry = NULL;

    klist_iter_init((struct klist *)&table->list, &list_iter);
    current_entry = (connection_entry_t *)klist_next(&list_iter);

    while (NULL != current_entry) {
        next_entry = (connection_entry_t *)klist_next(&list_iter);
        klist_del(&current_entry->node);
        CONNECTION_ENTRY_destroy(current_entry);
        current_entry = next_entry;
    }

    klist_iter_exit(&list_iter);
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
    const connection_entry_t *node = NULL;
    const size_t entry_dump_size = sizeof(*node->client) + sizeof(*node->server);
    size_t remaining_length = 0;
    size_t current_index = 0;

    if ((NULL == table) || (NULL == buffer) || (NULL == buffer_size_inout)) {
        goto l_cleanup;
    }
    
    remaining_length = *buffer_size_inout;

    /* XXX: Must discard the const, but not modifying it */
    klist_iter_init((struct klist *)&table->list, &list_iter);

    printk(KERN_INFO "%s: enter, buffer size %lu\n", __func__, (unsigned long)remaining_length);
    while (remaining_length > entry_dump_size) {
        /* 1. Get next chunk  */
        node = (connection_entry_t *)klist_next(&list_iter); 
        printk(KERN_INFO "%s: node scanned 0x%.8x\n", __func__, (uint32_t)node);
        /* 2. Last chunk? break */
        if (NULL == node) {
            break;
        }

        /* printk(KERN_INFO "%s: copying an entry 0x%.8x:0x%.4x -> 0x%.8x->0x%.4x\n", __func__, node->conn.id.src_ip, node->conn.id.src_port, node->conn.id.dst_ip, node->conn.id.dst_port); */
        (void)memcpy(&buffer[current_index], node->client, sizeof(*node->client));
        current_index += sizeof(*node->client);
        (void)memcpy(&buffer[current_index], node->server, sizeof(*node->server));
        current_index += sizeof(*node->server);

        remaining_length -= entry_dump_size;
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
                  connection_entry_t *entry,
                  entry_cmp_result_t cmp_result)
{
    bool_t is_legal_traffic = TRUE;
    struct tcphdr *tcp_header = tcp_hdr(skb);
    connection_t *sender = NULL;
    connection_t *receiver = NULL;

    /* 1. Initialize sender and receiver */
    switch (cmp_result)
    {
    case ENTRY_CMP_FROM_CLIENT:
    case ENTRY_CMP_TO_SERVER:
        sender = entry->client;
        receiver = entry->server;
        break;
    case ENTRY_CMP_FROM_SERVER:
    case ENTRY_CMP_TO_CLIENT:
        sender = entry->server;
        receiver = entry->client;
        break;
    case ENTRY_CMP_MISMATCH:
    default:
        printk(KERN_ERR "%s (skb=%s): given entry %p doesn't match\n", __func__, SKB_str(skb), entry);
        is_legal_traffic = FALSE;
        goto l_cleanup;
    }

    /* 2. Check RST */
    if (tcp_header->rst) {
        remove_entry(entry);
        goto l_cleanup;
    }

    /* printk(KERN_INFO "%s (skb=%s): hello\n", __func__, SKB_str(skb)); */
    /* 3. Handle TCP state machine */
    printk(KERN_INFO "%s (skb=%s): state %d\n", __func__, SKB_str(skb), sender->state);
    switch (sender->state)
    {
    case TCP_CLOSE:
        if (tcp_header->syn) {
            if (!tcp_header->ack) {
            printk(KERN_INFO "%s (skb=%s): state CLOSE got syn!\n", __func__, SKB_str(skb));
            sender->state = TCP_SYN_SENT;
            receiver->state = TCP_SYN_RECV;
            } else {
                printk(KERN_INFO "%s (skb=%s): state CLOSE got syn-ack - illegal\n", __func__, SKB_str(skb));
                is_legal_traffic = FALSE;
                goto l_cleanup;
            }
        } else {
            is_legal_traffic = FALSE;
            goto l_cleanup;
        }
        break;
    case TCP_ESTABLISHED:
        /* SYN is illegal, FIN is legal (and closes), everything else is legal */
        if (tcp_header->fin) {
            /* printk(KERN_INFO "%s (skb=%s): state %d got fin\n", __func__, SKB_str(skb), sender->state); */
            sender->state = TCP_FIN_WAIT1;
            receiver->state = TCP_CLOSE_WAIT;
        } else if (tcp_header->syn) {
            /* Detect invalid traffic */
            printk(KERN_INFO "%s (skb=%s): state %d illegal traffic with syn\n", __func__, SKB_str(skb), sender->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        } else {
            /* Default: action remains NF_ACCEPT */
        } 
        break;
    case TCP_SYN_SENT:
        /* Allowed only ACK */
        if (tcp_header->fin || (!tcp_header->ack)) {
            printk(KERN_INFO "%s (skb=%s): state %d illegal traffic\n", __func__, SKB_str(skb), sender->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        } else if (tcp_header->ack) {
            /* printk(KERN_INFO "%s (skb=%s): state %d got ack\n", __func__, SKB_str(skb), sender->state); */
            sender->state = TCP_ESTABLISHED;
            receiver->state = TCP_ESTABLISHED;
        }
        break;
    case TCP_SYN_RECV:
        /* Nothing should be sent after SYN+ACK - drop the connection.
         * Note: it might be accepted later and its not our concern */
        if (tcp_header->syn && tcp_header->ack) {
            /* printk(KERN_INFO "%s (skb=%s): state %d got synack\n", __func__, SKB_str(skb), sender->state); */
            sender->state = TCP_ESTABLISHED;
            receiver->state = TCP_ESTABLISHED;
        } else if (tcp_header->fin) {
            /* printk(KERN_INFO "%s (skb=%s): state %d got fin\n", __func__, SKB_str(skb), sender->state); */
            sender->state = TCP_CLOSE_WAIT;
            receiver->state = TCP_FIN_WAIT1;
        } else {
            printk(KERN_INFO "%s (skb=%s): state %d got illegal traffic\n", __func__, SKB_str(skb), sender->state);
            is_legal_traffic = FALSE;
            goto l_cleanup;
        }
        break;
    case TCP_FIN_WAIT1:
        if (tcp_header->fin) {
            if (tcp_header->ack) {
                /* printk(KERN_INFO "%s (skb=%s): state %d got finack\n", __func__, SKB_str(skb), sender->state); */
                sender->state = TCP_TIME_WAIT;
                receiver->state = TCP_CLOSING;
            } else {
                /* printk(KERN_INFO "%s (skb=%s): state %d got fin\n", __func__, SKB_str(skb), sender->state); */
                sender->state = TCP_CLOSING;
                receiver->state = TCP_TIME_WAIT;
            }
        } else if (tcp_header->ack) {
            /* printk(KERN_INFO "%s (skb=%s): state %d got ack\n", __func__, SKB_str(skb), sender->state); */
            sender->state = TCP_FIN_WAIT2;
            receiver->state = TCP_CLOSE_WAIT;
        }
        break;
    case TCP_FIN_WAIT2:
        if (tcp_header->fin) {
            /* printk(KERN_INFO "%s (skb=%s): state %d got fin\n", __func__, SKB_str(skb), sender->state); */
            sender->state = TCP_TIME_WAIT;
            receiver->state = TCP_CLOSING;
        }
        break;
    case TCP_CLOSING:
        if (tcp_header->ack) {
            /* printk(KERN_INFO "%s (skb=%s): state %d got ack\n", __func__, SKB_str(skb), sender->state); */
            sender->state = TCP_TIME_WAIT;
            receiver->state = TCP_FIN_WAIT2;
        }
        break;
    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
        /* printk(KERN_INFO "%s (skb=%s): state %d discarding\n", __func__, SKB_str(skb), sender->state); */
        remove_entry(entry);
        break;
    case TCP_CLOSE_WAIT:
        if (tcp_header->ack) {
            /* printk(KERN_INFO "%s (skb=%s): state %d got ack\n", __func__, SKB_str(skb), sender->state); */
            sender->state = TCP_LAST_ACK;
            receiver->state = TCP_TIME_WAIT;
        }
        break;
    default:
        printk(KERN_INFO "%s (skb=%s): state %d UNKNOWN! discarding\n", __func__, SKB_str(skb), sender->state);
        is_legal_traffic = FALSE;
        goto l_cleanup;
    }

l_cleanup:

    return is_legal_traffic;
}

bool_t
CONNECTION_TABLE_track_local_out(connection_table_t *table,
                                 struct sk_buff *skb)
{
    bool_t was_handled = FALSE;
    connection_entry_t *entry = NULL;
    bool_t is_proxy_connection = FALSE;
    entry_cmp_result_t cmp_result = ENTRY_CMP_MISMATCH;

    /* 0. Input validation */
    if ((NULL == table) || (NULL == skb)) {
        printk(KERN_WARNING "CONNECTION_TABLE_check got invalid input\n");
        goto l_cleanup;
    }

    /* 1. Check if exists on the table */
    /* Note: For SYN packets it won't match, and the handling will be done here...
     *       Unless, a connection exists for this SYN packet, and it will be handled accordingly */
    cmp_result = search_entry(&table->list, skb, &entry);
    if (ENTRY_CMP_MISMATCH == cmp_result) {
        /* printk(KERN_INFO "%s (skb=%s): no entry for 0x%.8x:0x%.4x -> 0x%.8x->0x%.4x\n", __func__, SKB_str(skb), ip_hdr(skb)->saddr, tcp_hdr(skb)->source, ip_hdr(skb)->daddr, tcp_hdr(skb)->dest); */
        goto l_cleanup;
    }

    is_proxy_connection = IS_PROXY_ENTRY(entry);
    if (is_proxy_connection) {
        CONNECTION_ENTRY_hook(entry, skb);

        /* switch (conn->state) */
        /* { */
        /*     caseswitch (conn->state) */
        /*     { */
        /*         case  */
    }

l_cleanup:

    return was_handled;
}

entry_cmp_result_t
CONNECTION_TABLE_check(connection_table_t *table,
                       struct sk_buff *skb,
                       __u8 *action_out,
                       reason_t *reason_out)
{
    entry_cmp_result_t cmp_result = ENTRY_CMP_MISMATCH;
    bool_t is_legal_traffic = TRUE;
    connection_entry_t *entry = NULL;

    /* 0. Input validation */
    if ((NULL == table) || (NULL == skb) || (NULL == action_out) || (NULL == reason_out)) {
        printk(KERN_WARNING "CONNECTION_TABLE_check got invalid input\n");
        goto l_cleanup;
    }

    /* 1. Filter non_TCP packets */
    if (htons(ETH_P_IP) != skb->protocol) {

        printk(KERN_ERR "%s: skb is not ip!\n", __func__);
        goto l_cleanup;
    }
    if (IPPROTO_TCP != ip_hdr(skb)->protocol) {
        if (htons(ETH_P_IP) != skb->protocol) {
            printk(KERN_ERR "%s: skb is not ip!\n", __func__);
        }
        printk(KERN_INFO "%s: ignoring non-tcp packet %p\n", __func__, skb);
        goto l_cleanup;
    }

    /* 1. Check if exists on the table */
    /* Note: For SYN packets it won't match, and the handling will be done here...
     *       Unless, a connection exists for this SYN packet, and it will be handled accordingly */
    cmp_result = search_entry(&table->list, skb, &entry);
    if (ENTRY_CMP_MISMATCH == cmp_result) {
        printk(KERN_INFO "%s (skb=%s): no entry\n", __func__, SKB_str(skb));
        goto l_cleanup;
    }

    is_legal_traffic = tcp_machine_state(table, skb, entry, cmp_result);
    /* 3. Check if the traffic is legal, drop illegal traffic */
    if (is_legal_traffic) {
        *action_out = NF_ACCEPT;
        /* TODO: Don't log */
        *reason_out = 0;
    } if (!is_legal_traffic) {
        /* Drop the entry */
        remove_entry(entry);
        *action_out = NF_DROP;
        *reason_out = REASON_ILLEGAL_VALUE;
        goto l_cleanup;
    }

    /* 6. Call the hook */
    CONNECTION_ENTRY_hook(entry, skb);

l_cleanup:

    return cmp_result;
}

result_t
CONNECTION_TABLE_handle_accepted_syn(connection_table_t *table,
                                     const struct sk_buff *skb)
{
    result_t result = E__UNKNOWN;
    connection_entry_t *entry = NULL;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    /* 0. Input validation */
    /* 0.1. NULL validation */
    if ((NULL == table) || (NULL == skb)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 0.2. TCP SYN validation */
    ip_header = ip_hdr(skb);
    if (IPPROTO_TCP != ip_header->protocol) {
        result = E__SUCCESS;
        goto l_cleanup;
    }
    tcp_header = tcp_hdr(skb);
    if (!is_syn_packet(tcp_header)) {
        result = E__SUCCESS;
        goto l_cleanup;
    }

    /* 1. Create connection entry */
    result = CONNECTION_ENTRY_create_from_syn(&entry, skb);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 2. Add to entries list */
    klist_add_tail(&entry->node, &table->list);
    printk(KERN_INFO "%s (skb=%s): added entry to table->list\n", __func__, SKB_str(skb));

    /* TODO: If you add logic that can fail, make sure to clean the entry from
     *       the tables upon failure */

    /* Success */
    result = E__SUCCESS;
l_cleanup:
    if (E__SUCCESS != result) {
        CONNECTION_ENTRY_destroy(entry);
        entry = NULL;
    }

    return result;
}

static entry_cmp_result_t
search_entry(struct klist *entries_list,
             const struct sk_buff *skb,
             connection_entry_t **entry_out)
{
    entry_cmp_result_t cmp_result = ENTRY_CMP_MISMATCH;
    connection_entry_t *entry = NULL;
    struct klist_iter list_iter = {0};

    klist_iter_init(entries_list, &list_iter);

    /* printk(KERN_INFO "%s: searching id 0x%.8x:0x%.4x -> 0x%.8x:0x%.4x\n", __func__, id->src_ip, id->src_port, id->dst_ip, id->dst_port); */
    while (TRUE) {
        /* 1. Get the next entry from the list */
        entry = (connection_entry_t *)klist_next(&list_iter); 
        /* printk(KERN_INFO "%s: entry 0x%.8x\n", __func__, (uint32_t)entry); */
        /* 2. Last entry? break */
        if (NULL == entry) {
            break;
        }

        /* 3. Check if matches */
        cmp_result = CONNECTION_ENTRY_compare(entry, skb);
        if (ENTRY_CMP_MISMATCH != cmp_result) {
            /* 4. On match - return the entry and stop the iteration */
            *entry_out = entry;
            break;
        }
    }

    klist_iter_exit(&list_iter);

    return cmp_result;
}

static void
remove_entry(connection_entry_t *entry)
{
    if (NULL != entry) {
        klist_del(&entry->node);
        CONNECTION_ENTRY_destroy(entry);
        entry = NULL;
    }
}

