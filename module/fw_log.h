/**
 * @file fw_log.h
 * @author Assaf Gadish
 *
 * @brief Logging system of the firewall
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
#include "fw_results.h"


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief Initialise an empty rule table
 * 
 * @param[init] The new table
 *
 * @return TRUE on success, FALSE on failure
 */
void
FW_LOG_init(void);

/**
 * @brief Free the logs and cleanup the module. Must be called before exit
 */
void
FW_LOG_shutdown(void);

/**
 * @brief Log a given packet, caused a given action, by a given reason
 * 
 * @param[in] skb The packet that caused the match
 * @param[in] reason Either one of reason_t values or (reason_t)index, with the
 *                   index of the matching rule
 * @param[in] action The action done (NF_ACCEPT/NF_DROP)
 *
 * @return E__SUCCESS on success, other result_t values on failure
 */
result_t
FW_LOG_log_match(const struct sk_buff *skb, 
                 __u8 action,
                 reason_t reason);

/**
 * @brief Copy the logs to a userspace buffer (using copy_from_user)
 * 
 * @param[in] out_buffer The userspace buffer to copy to
 * @param[in] buffer_size Size of out_buffer
 * @param[inout] offset_inout The offset of the logs, aka number of log bytes
 *                            that were already copied. Will be increased with
 *                            the number of bytes this function writes
 *
 * @return Number of bytes that were written
 */
size_t
FW_LOG_dump(uint8_t __user *out_buffer,
            size_t buffer_size,
            loff_t *offset_inout);

/**
 * @brief Clear the logs buffer and free all the underlying memory
 */
void
FW_LOG_reset_logs(void);


#endif /* __FW_LOG_H__ */
