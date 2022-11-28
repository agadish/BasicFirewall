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

/*    T Y P E D E F S   */
typedef struct log_dump_context_s log_dump_context_t;


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

void
FW_LOG_shutdown(void);

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
result_t
FW_LOG_log(const log_row_t *log);


/**
 * @brief Create a dump context. Required to call before performing a log dump
 * 
 * @param[out] context_out The new log context
 *
 * @return E__SUCCESS on success, other value on error.
 *
 * @remark On error, NULL will be written into context_out (if it's not NULL)
 */
result_t
FW_LOG_init_dump_context(log_dump_context_t **context_out);

result_t
FW_LOG_dump(log_dump_context_t *context,
            uint8_t *out_buffer,
            size_t buffer_size,
            size_t *bytes_written_out);

void
FW_LOG_release_dump_context(log_dump_context_t *context);

void
FW_LOG_reset_logs(void);


#endif /* __FW_LOG_H__ */
