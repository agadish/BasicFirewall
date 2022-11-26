/**
 * @file fw_log.h
 * @author Assaf Gadish
 *
 * @brief Rule table chaining and execution
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
#ifndef __FW_LOG_H__
#define __FW_LOG_H__
/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>

#include "fw.h"
#include "common.h"
#include "fw_log.h"

/*    T Y P E D E F S   */
typedef struct fw_log_s fw_log_t;


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief Initialise an empty rule table
 * 
 * @param[init] The new table
 *
 * @return TRUE on success, FALSE on failure
 */
void
FW_LOG_init(fw_log_t *table);

/**
 * @brief Destroy a rule table
 * 
 * @param[in] Table to set the data to 
 * @param[in] Data to set
 * @param[in] Length of data to set
 *
 * @return TRUE if was set succesfully, FALSE otherwise (probably due to
 *         invalid data)
 *
 * @remark On any failure (for example if invalid data was given), the function
 *         will reset the data, discarding the previous rules if existed.
 */
bool_t
FW_LOG_set_data(fw_log_t *table,
                    const uint8_t *data,
                    size_t data_length);

/**
 * @brief Match a given packet against the whole rule table, and return the
 *        required action
 * 
 * @param[in] table Table with the rules
 * @param[in] skb The packet to check
 * @param[out] action_out The decision made by the function, valid only if the
 *             function returned TRUE. can be eiter NF_ACCEPT or NF_DROP
 *
 * @return NF_ACCEPT or NF_DROP
 *
 * @remark If the packet doesn't match the table then nothing will be written
 *         to action_out parameter
 */
bool_t
FW_LOG_check(const fw_log_t *table,
                 const struct sk_buff *skb,
                 __u8 *action_out)


#endif /* __FW_LOG_H__ */
