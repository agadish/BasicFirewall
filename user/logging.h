/**
 * @file logging.h
 * @author Assaf Gadish
 *
 * @brief Rule table functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

#ifndef __LOGGIG_H__
#define __LOGGIG_H__

/*   I N C L U D E S    */
#include "results.h"
#include "fw_user.h"


/*   M A C R O S   */
#define READ_LOGS_PATH "/dev/fw_log"
#define RESET_LOGS_PATH "/sys/class/fw/log/reset"


/*   F U N C T I O N S   D E C L A R A T I O N S   */
result_t
LOGGIG_print_logs(const char *read_logs_path);

result_t
LOGGIG_reset_logs(const char *reset_logs_path);


#endif /* __LOGGIG_H__ */

