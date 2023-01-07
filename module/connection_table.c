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
#include "net_utils.h"

#include "connection_entry.h"
#include "connection_table.h"


/*    S T R U C T S   */
struct connection_table_s {
    struct klist list;
};


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief Update the states of the sender and the receiver due to a given packet
 *
 * @param[inout] sender The packet's sender single connection
 * @param[inout] receiver The packet's receiver single connection
 * @param[in] skb The packet
 *
 * @return TRUE if at least one of the single connection was closed,
 *         otherwise FALSE
 */
static bool_t
tcp_machine_state(single_connection_t *sender,
                  single_connection_t *receiver,
                  const struct sk_buff *skb);

/**
 * @brief Search an entry by a given packet that was captured in PRE_ROUTING
 *
 * @param[in] entries_list The list of all entries
 * @param[in] skb The packet arrived
 * @param[out] entry_out The result entry, if found
 *
 * @return PACKET_DIRECTION_MISMATCH    if not found, otherwise the matching
 *         PACKET_DIRECTION_FROM_CLIENT if sent from the client
 *         PACKET_DIRECTION_FROM_SERVER if sent from the server
 */
static packet_direction_t
search_entry__pre_routing(struct klist *entries_list,
                          const struct sk_buff *skb,
                          connection_entry_t **entry_out);

/**
 * @brief Search an entry by a given packet that was captured in LOCAL_OUT
 *
 * @param[in] entries_list The list of all entries
 * @param[in] skb The packet arrived
 * @param[out] entry_out The result entry, if found
 *
 * @return PACKET_DIRECTION_MISMATCH    if not found, otherwise the matching
 *         PACKET_DIRECTION_TO_CLIENT if sent to the client
 *         PACKET_DIRECTION_TO_SERVER if sent to the server
 */
static packet_direction_t
search_entry__local_out(struct klist *entries_list,
                        const struct sk_buff *skb,
                        connection_entry_t **entry_out);

/**
 * @brief Notify that at least one of the single_connection_t's within an entry
 *        is closed. The function will check if all the single connections are
 *        closed, and call _remove_entry accordingly
 *
 * @param[in] entry The entry to check
 */
static void
entry_notify_connection_closed(connection_entry_t *entry);

/**
 * @brief Remove an entry from the connection table
 *
 * @param[in] entry The entry to remove
 *
 * @remark Use entry_notify_connection_closed to remove an established
 *         connection. It will be removed once it's fully closed.
 */
static void
_remove_entry(connection_entry_t *entry);


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

    /* 1. Initialise an iterator on the table */
    klist_iter_init((struct klist *)&table->list, &list_iter);
    current_entry = (connection_entry_t *)klist_next(&list_iter);

    /* 2. Remove each entry from the list and detroy its internals */
    while (NULL != current_entry) {
        next_entry = (connection_entry_t *)klist_next(&list_iter);
        klist_del(&current_entry->node);
        CONNECTION_ENTRY_destroy(current_entry);
        current_entry = next_entry;
    }

    /* 3. Clean the iterator */
    klist_iter_exit(&list_iter);
}

bool_t
CONNECTION_TABLE_dump_data(const connection_table_t *table,
                     uint8_t *buffer,
                     size_t *buffer_size_inout)
{
    bool_t result = FALSE;
    struct klist_iter list_iter = {0};
    const connection_entry_t *entry = NULL;
    size_t remaining_length = 0;
    size_t current_length = 0;
    size_t current_index = 0;

    if ((NULL == table) || (NULL == buffer) || (NULL == buffer_size_inout)) {
        goto l_cleanup;
    }
    
    remaining_length = *buffer_size_inout;

    /* XXX: Must discard the const, but not modifying it */
    klist_iter_init((struct klist *)&table->list, &list_iter);

    while (remaining_length > 0) {
        /* 1. Get next chunk  */
        entry = (connection_entry_t *)klist_next(&list_iter); 
        /* 2. Last chunk? break */
        if (NULL == entry) {
            result = TRUE;
            break;
        }

        current_length = CONNECTION_ENTRY_dump(entry,
                                               &buffer[current_index],
                                               remaining_length);
        if (0 == current_length) {
            break;
        }
        current_index += current_length;
        remaining_length -= current_length;
    }

    klist_iter_exit(&list_iter);

    *buffer_size_inout = current_index;

l_cleanup:

    return result;
}

static bool_t
tcp_machine_state(single_connection_t *sender,
                  single_connection_t *receiver,
                  const struct sk_buff *skb)
{
    bool_t is_closed = FALSE;
    struct tcphdr *tcp_header = tcp_hdr(skb);

    /* 1. Check RST */
    if (tcp_header->rst) {
        sender->state = TCP_CLOSE;
        receiver->state = TCP_CLOSE;
        is_closed = TRUE;
        goto l_cleanup;
    }

    /* 2. Handle TCP state machine */
    switch (sender->state)
    {
    case TCP_CLOSE:
        if (tcp_header->syn) {
            if (!tcp_header->ack) {
                sender->state = TCP_SYN_SENT;
                receiver->state = TCP_SYN_RECV;
            } else {
                goto l_cleanup;
            }
        } else {
            goto l_cleanup;
        }
        break;

    case TCP_ESTABLISHED:
        /* SYN is illegal, FIN is legal (and closes).
         * Everything else is legal */
        if (tcp_header->fin) {
            sender->state = TCP_FIN_WAIT1;
            receiver->state = TCP_CLOSE_WAIT;
        } else if (tcp_header->syn) {
            /* Detect invalid traffic */
            goto l_cleanup;
        } else {
            /* Default: action remains NF_ACCEPT */
        } 
        break;

    case TCP_SYN_SENT:
        /* Allowed only ACK */
        if (tcp_header->fin || (!tcp_header->ack)) {
            goto l_cleanup;
        } else if (tcp_header->ack) {
            sender->state = TCP_ESTABLISHED;
            receiver->state = TCP_ESTABLISHED;
        }
        break;

    case TCP_SYN_RECV:
        /* Nothing should be sent after SYN+ACK - drop the connection.
         * Note: it might be accepted later and its not our concern */
        if (tcp_header->syn && tcp_header->ack) {
            sender->state = TCP_ESTABLISHED;
            receiver->state = TCP_ESTABLISHED;
        } else if (tcp_header->fin) {
            sender->state = TCP_CLOSE_WAIT;
            receiver->state = TCP_FIN_WAIT1;
        } else {
            goto l_cleanup;
        }
        break;

    case TCP_FIN_WAIT1:
        if (tcp_header->fin) {
            if (tcp_header->ack) {
                sender->state = TCP_TIME_WAIT;
                receiver->state = TCP_CLOSING;
            } else {
                sender->state = TCP_CLOSING;
                receiver->state = TCP_TIME_WAIT;
            }
        } else if (tcp_header->ack) {
            sender->state = TCP_FIN_WAIT2;
            receiver->state = TCP_CLOSE_WAIT;
        }
        break;

    case TCP_FIN_WAIT2:
        if (tcp_header->fin) {
            sender->state = TCP_TIME_WAIT;
            receiver->state = TCP_CLOSING;
        }
        break;

    case TCP_CLOSING:
        if (tcp_header->ack) {
            sender->state = TCP_TIME_WAIT;
            receiver->state = TCP_FIN_WAIT2;
        }
        break;

    case TCP_LAST_ACK:
    case TCP_TIME_WAIT:
        sender->state = TCP_CLOSE;
        receiver->state = TCP_CLOSE;
        is_closed = TRUE;
        break;

    case TCP_CLOSE_WAIT:
        if (tcp_header->ack) {
            sender->state = TCP_LAST_ACK;
            receiver->state = TCP_TIME_WAIT;
        }
        break;

    default:
        printk(KERN_ERR "%s (skb=%s): state %d UNKNOWN! discarding\n",
                __func__, SKB_str(skb), sender->state);
        goto l_cleanup;
    }

l_cleanup:

    return is_closed;
}

packet_direction_t
CONNECTION_TABLE_check_pre_routing(connection_table_t *table,
                       struct sk_buff *skb,
                       __u8 *action_out)
{
    packet_direction_t cmp_result = PACKET_DIRECTION_MISMATCH;
    connection_entry_t *entry = NULL;
    single_connection_t *conn_sender = NULL;
    single_connection_t *conn_receiver = NULL;
    bool_t result_get_conn = FALSE;
    bool_t is_closed = FALSE;

    /* 0. Input validation */
    if ((NULL == table) || (NULL == skb) || (NULL == action_out)) {
        printk(KERN_ERR "CONNECTION_TABLE_check_pre_routing got invalid input\n");
        goto l_cleanup;
    }

    /* 1. Filter non-TCP packets */
    if (htons(ETH_P_IP) != skb->protocol) {
        printk(KERN_ERR "%s: skb is not ip!\n", __func__);
        goto l_cleanup;
    }
    if (IPPROTO_TCP != ip_hdr(skb)->protocol) {
        if (htons(ETH_P_IP) != skb->protocol) {
            printk(KERN_ERR "%s: skb is not ip!\n", __func__);
        }
        goto l_cleanup;
    }

    /* 1. Check if exists on the table */
    /* Note: For SYN packets it won't match, and the handling will be done
     *       here... Unless, a connection exists for this SYN packet, and it
     *       will be handled accordingly */
    cmp_result = search_entry__pre_routing(&table->list, skb, &entry);
    if (PACKET_DIRECTION_MISMATCH == cmp_result) {
        goto l_cleanup;
    }

    /* 3. Get sender and receiver */
    result_get_conn = CONNECTION_ENTRY_get_conns_by_direction(entry,
                                                              cmp_result,
                                                              &conn_sender,
                                                              &conn_receiver);
    if (!result_get_conn) {
        printk(KERN_ERR "%s (skb=%s): invalid get conn\n",
                __func__, SKB_str(skb));
        _remove_entry(entry);
        *action_out = NF_DROP;
        goto l_cleanup;
    }

    /* 4. Handle TCP state machine */
    /* 4.1. Update the machine state */
    is_closed = tcp_machine_state(conn_sender, conn_receiver, skb);
    if (is_closed) {
        /* 4.2. Softly close the connection */
        entry_notify_connection_closed(entry);
        goto l_cleanup;
    }

    /* 5. Call the hook */
    CONNECTION_ENTRY_pre_routing_hook(entry, skb, cmp_result);

l_cleanup:

    return cmp_result;
}

packet_direction_t
CONNECTION_TABLE_check_local_out(connection_table_t *table,
                       struct sk_buff *skb)
{
    packet_direction_t cmp_result = PACKET_DIRECTION_MISMATCH;
    connection_entry_t *entry = NULL;
    single_connection_t *conn_sender = NULL;
    single_connection_t *conn_receiver = NULL;
    bool_t result_get_conn = FALSE;
    bool_t is_closed = FALSE;

    /* 0. Input validation */
    if ((NULL == table) || (NULL == skb)) {
        printk(KERN_ERR "CONNECTION_TABLE_check_pre_routing got invalid input\n");
        goto l_cleanup;
    }

    /* 1. Filter non-TCP packets */
    if (htons(ETH_P_IP) != skb->protocol) {
        printk(KERN_ERR "%s: skb is not ip!\n", __func__);
        goto l_cleanup;
    }
    if (IPPROTO_TCP != ip_hdr(skb)->protocol) {
        if (htons(ETH_P_IP) != skb->protocol) {
            printk(KERN_ERR "%s: skb is not ip!\n", __func__);
        }
        goto l_cleanup;
    }

    /* 1. Check if exists on the table */
    /* Note: For SYN packets it won't match, and the handling will be done
     *       here... Unless, a connection exists for this SYN packet, and it
     *       will be handled accordingly */
    cmp_result = search_entry__local_out(&table->list, skb, &entry);
    if (PACKET_DIRECTION_MISMATCH == cmp_result) {
        goto l_cleanup;
    }

    /* 3. Get sender and receiver */
    result_get_conn = CONNECTION_ENTRY_get_conns_by_direction(entry,
                                                              cmp_result,
                                                              &conn_sender,
                                                              &conn_receiver);
    if (!result_get_conn) {
        printk(KERN_ERR "%s (skb=%s): invalid get conn\n",
                __func__, SKB_str(skb));
        _remove_entry(entry);
        goto l_cleanup;
    }

    /* 4. Handle TCP state machine */
    is_closed = tcp_machine_state(conn_sender, conn_receiver, skb);
    /* 3. Check if the traffic is legal, drop illegal traffic */
    if (is_closed) {
        entry_notify_connection_closed(entry);
        goto l_cleanup;
    }

    /* 6. Call the hook */
    CONNECTION_ENTRY_local_out_hook(entry, skb, cmp_result);

l_cleanup:

    return cmp_result;
}

result_t
CONNECTION_TABLE_add_by_skb(connection_table_t *table,
                            const struct sk_buff *skb)
{
    result_t result = E__UNKNOWN;
    connection_entry_t *entry = NULL;

    /* 0. Input validation */
    /* 0.1. NULL validation */
    if ((NULL == table) || (NULL == skb)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Create connection entry */
    result = CONNECTION_ENTRY_create_from_skb(&entry, skb);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 2. Add to entries list */
    klist_add_tail(&entry->node, &table->list);

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

static packet_direction_t
search_entry__local_out(struct klist *entries_list,
                        const struct sk_buff *skb,
                        connection_entry_t **entry_out)
{
    packet_direction_t cmp_result = PACKET_DIRECTION_MISMATCH;
    connection_entry_t *entry = NULL;
    struct klist_iter list_iter = {0};

    klist_iter_init(entries_list, &list_iter);

    while (TRUE) {
        /* 1. Get the next entry from the list */
        entry = (connection_entry_t *)klist_next(&list_iter); 
        /* 2. Last entry? break */
        if (NULL == entry) {
            break;
        }

        /* 3. Check if matches */
        cmp_result = CONNECTION_ENTRY_cmp_local_out(entry, skb);
        if (PACKET_DIRECTION_MISMATCH != cmp_result) {
            /* 4. On match - return the entry and stop the iteration */
            *entry_out = entry;
            break;
        }
    }

    klist_iter_exit(&list_iter);

    return cmp_result;
}

static packet_direction_t
search_entry__pre_routing(struct klist *entries_list,
             const struct sk_buff *skb,
             connection_entry_t **entry_out)
{
    packet_direction_t cmp_result = PACKET_DIRECTION_MISMATCH;
    connection_entry_t *entry = NULL;
    struct klist_iter list_iter = {0};

    klist_iter_init(entries_list, &list_iter);

    while (TRUE) {
        /* 1. Get the next entry from the list */
        entry = (connection_entry_t *)klist_next(&list_iter); 
        /* 2. Last entry? break */
        if (NULL == entry) {
            break;
        }

        /* 3. Check if matches */
        cmp_result = CONNECTION_ENTRY_cmp_pre_routing(entry, skb);
        if (PACKET_DIRECTION_MISMATCH != cmp_result) {
            /* 4. On match - return the entry and stop the iteration */
            *entry_out = entry;
            break;
        }
    }

    klist_iter_exit(&list_iter);

    return cmp_result;
}

static void
entry_notify_connection_closed(connection_entry_t *entry)
{
    /* Garbage collector:
     * if all sub-connections are closed - entry can be removed */
    if (CONNECTION_ENTRY_is_closed(entry)) {
        _remove_entry(entry);
    }
}

static void
_remove_entry(connection_entry_t *entry)
{
    if (NULL != entry) {
        klist_del(&entry->node);
        CONNECTION_ENTRY_destroy(entry);
        entry = NULL;
    }
}

result_t
CONNECTION_TABLE_remove_by_skb(connection_table_t *table,
                               const struct sk_buff *skb)
{
    result_t result = E__UNKNOWN;
    packet_direction_t direction = PACKET_DIRECTION_MISMATCH;
    connection_entry_t *entry = NULL;


    /* 0. Input validation */
    if ((NULL == table) || (NULL == skb)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Search the entry */
    direction = search_entry__pre_routing(&table->list,
                                          skb,
                                          &entry);
    /* If entry not found - return success */
    if (PACKET_DIRECTION_MISMATCH != direction) {
        /* 2. Remove it */
        _remove_entry(entry);
    }

    result = E__SUCCESS;
l_cleanup:

    return result;
}

result_t
CONNECTION_TABLE_add_by_id(connection_table_t *table,
                           const connection_id_t *id)
{
    result_t result = E__UNKNOWN;
    connection_entry_t *entry = NULL;
    
    /* 0. Input validation */
    if ((NULL == table) || (NULL == id)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Create connection entry */
    result = CONNECTION_ENTRY_create_from_id(&entry, id);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 2. Add to entries list */
    klist_add_tail(&entry->node, &table->list);

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

