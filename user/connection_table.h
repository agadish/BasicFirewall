/**
 * @file connection_table.h
 * @author Assaf Gadish
 *
 * @brief Connection table functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

#ifndef __CONNECTION_TABLE_H__
#define __CONNECTION_TABLE_H__

/*   I N C L U D E S    */
#include "results.h"
#include "fw_user.h"


/*   M A C R O S   */
#define CONNS_FILE_PATH "/sys/class/fw/conns/conns"


/*   F U N C T I O N S   D E C L A R A T I O N S   */
result_t
CONNECTION_TABLE_print_table(const char *read_conns_path);


#endif /* __CONNECTION_TABLE_H__ */

