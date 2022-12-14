/**
 * @file rule_table.h
 * @author Assaf Gadish
 *
 * @brief Rule table functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

#ifndef __RULE_TABLE_H__
#define __RULE_TABLE_H__

/*   I N C L U D E S    */
#include "results.h"
#include "fw_user.h"


/*   M A C R O S   */
#define RULES_FILE_PATH "/sys/class/fw/rules/rules"


/*   F U N C T I O N S   D E C L A R A T I O N S   */
result_t
RULE_TABLE_bin_to_human(rule_table_t *rule_table_out, const char *path);

result_t
RULE_TABLE_human_to_bin(rule_table_t *rule_table_out, const char *path);

result_t
RULE_TABLE_print_table(rule_table_t *rule_table);

result_t
RULE_TABLE_write_bin(rule_table_t *rule_table, const char *path);


#endif /* __RULE_TABLE_H__ */

