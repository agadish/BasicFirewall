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
#include "fw_results.h"


/*   T Y P E D E F S   */
typedef struct connection_table_s connection_table_t;


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief Initialise an empty connection table
 * 
 * @param[init] The new table
 *
 * @return One of result_t values
 *
 * @remark Must be destroyed with CONNECTION_TABLE_destroy
 */
result_t
CONNECTION_TABLE_create(connection_table_t **table_out);

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
 * @brief Match a given packet against the whole connection table, and return the
 *        required action
 * 
 * @param[in] table Table with the connections
 * @param[in] skb The packet to check
 * @param[out] action_out The decision made by the function, valid only if the
 *             function returned TRUE. can be eiter NF_ACCEPT or NF_DROP
 * @param[out] reason_out The reason to the decision. Can be either one of
 *                        reason_t values, or the connection id casted to reason_t.
 *
 * @return TRUE if packet matched a connection, otherwise FALSE
 *
 * @remark If the packet doesn't match the table then nothing will be written
 *         to action_out parameter
 */
bool_t
CONNECTION_TABLE_check(connection_table_t *table,
                       struct sk_buff *skb,
                       __u8 *action_out,
                       reason_t *reason_out);

result_t
CONNECTION_TABLE_assign_proxy(connection_table_t *table,
                              proxy_connection_t *proxy_conn);

result_t
CONNECTION_TABLE_handle_accepted_syn(connection_table_t *table,
                                     const struct sk_buff *skb);
bool_t
CONNECTION_TABLE_track_local_out(connection_table_t *table,
                                 const struct sk_buff *skb);


#endif /* __CONNECTION_TABLE_H__ */
