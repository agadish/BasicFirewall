/**
 * @file connection_table.h
 * @author Assaf Gadish
 *
 * @brief Connection table of TCP connections
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
#ifndef __CONNECTION_TABLE_H__
#define __CONNECTION_TABLE_H__
/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>

#include "fw.h"
#include "common.h"
#include "connection_entry.h"
#include "fw_results.h"


/*   T Y P E D E F S   */
typedef struct connection_table_s connection_table_t;


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief Allocate and initialise an empty connection table
 * 
 * @param[out] table_out The new table
 *
 * @return One of result_t values
 *
 * @remark Must be destroyed with CONNECTION_TABLE_destroy
 */
result_t
CONNECTION_TABLE_create(connection_table_t **table_out);

/**
 * @brief Frees a connection table and all the entries within it
 *
 * @param[in] table The table to destroy
 */
void
CONNECTION_TABLE_destroy(connection_table_t *table);

/**
 * @brief Dump the table to a given buffer
 * 
 * @param[in] table Table to set the data to 
 * @param[out] buffer The dumped table buffer
 * @param[inout] buffer_size_inout Contains the initial length of buffer param,
 *               will hold the number of bytes that actually were written
 *
 * @return TRUE on success, FALSE if failed to write due to insufficient space
 */
bool_t
CONNECTION_TABLE_dump_data(const connection_table_t *table,
                           uint8_t *buffer,
                           size_t *buffer_size_inout);

/**
 * @brief Check if a given packet from the PRE_ROUTING hook matches a rule in
 *        the table, update the table accordingly and call the enty's hook
 *        (may modify the packet), and return the matched direction
 * 
 * @param[in] table Table with the connections
 * @param[in] skb The packet to check
 * @param[out] action_out The decision made by the function, valid only if the
 *             function returned TRUE. can be eiter NF_ACCEPT or NF_DROP
 *
 * @return PACKET_DIRECTION_MISMATCH    if was not found nor handled
 *         PACKET_DIRECTION_FROM_CLIENT if sent from the client
 *         PACKET_DIRECTION_FROM_SERVER if sent from the server
 *
 * @remark If the packet doesn't match the table then nothing will be written
 *         to action_out parameter
 */
packet_direction_t
CONNECTION_TABLE_check_pre_routing(connection_table_t *table,
                                   struct sk_buff *skb,
                                   __u8 *action_out);

/**
 * @brief Check if a given packet from the LOCAL_OUT hook matches a rule in
 *        the table, update the table accordingly and call the enty's hook
 *        (may modify the packet), and return the matched direction
 * 
 * @param[in] table Table with the connections
 * @param[in] skb The packet to check
 * @param[out] action_out The decision made by the function, valid only if the
 *             function returned TRUE. can be eiter NF_ACCEPT or NF_DROP
 *
 * @return PACKET_DIRECTION_MISMATCH  if was not found nor handled
 *         PACKET_DIRECTION_TO_CLIENT if sent to the client
 *         PACKET_DIRECTION_TO_SERVER if sent to the server
 *
 * @remark If the packet doesn't match the table then nothing will be written
 *         to action_out parameter
 */
packet_direction_t
CONNECTION_TABLE_check_local_out(connection_table_t *table,
                       struct sk_buff *skb);

/**
 * @brief Create a new connection and add it to the table. The entry will be
 *        created from the given packet as its connection's opener
 *
 * @param[in] table The table to add to
 * @param[in] skb The opener packet
 *
 * @return E__SUCCESS on success, other result_t value on failure
 *
 */
result_t
CONNECTION_TABLE_add_by_skb(connection_table_t *table,
                            const struct sk_buff *skb);

/**
 * @brief Create a new connection and add it to the table. The entry will be
 *        created from the given connection id as its connection's opener
 *
 * @param[in] table The table to add to
 * @param[in] id The opener id
 *
 * @return E__SUCCESS on success, other result_t value on failure
 *
 */
result_t
CONNECTION_TABLE_add_by_id(connection_table_t *table,
                           const connection_id_t *id);

/**
 * @brief Remove the entry whose opener matches the given packet from the table
 *
 * @param[in] table The table to remove an entry from
 * @param[in] skb The packet to identify the entry opener that should be removed
 *
 * @return E__SUCCESS on success, other result_t value on failure
 */
result_t
CONNECTION_TABLE_remove_by_skb(connection_table_t *table,
                               const struct sk_buff *skb);


#endif /* __CONNECTION_TABLE_H__ */
