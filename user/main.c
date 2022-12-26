/**
 * @file main.c
 * @author Assaf Gadish
 *
 * @brief Userpsace program to interact with the firewall.
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

/*   I N C L U D E S    */
#include <stdio.h>
#include <string.h>

#include "results.h"
#include "fw_user.h"
#include "rule_table.h"
#include "logging.h"


/*   M A C R O S   */
#define SHOW_RULES_STR "show_rules"
#define LOAD_RULES_STR "load_rules"
#define SHOW_LOG_STR "show_log"
#define CLEAR_LOG_STR "clear_log"
#define LOGS_CLEAR_PATH "/sys/class/fw/log/reset"
#define LOGS_PRINT_PATH "/dev/fw_log"


/*   F U N C T I O N S    D E C L A R A T I O N S   */
static result_t show_rules(void);
static result_t load_rules(const char *rule_path);
static result_t show_log(void);
static result_t clear_log(void);


/*   F U N C T I O N S    I M P L E M E N T A T I O N S   */
static result_t
show_rules(void)
{
    result_t result = E__UNKNOWN;
    rule_table_t rule_table = {0};

    /* 1. Read rules */
    result = RULE_TABLE_bin_to_human(&rule_table, RULES_FILE_PATH);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 2. Print rules */
    result = RULE_TABLE_print_table(&rule_table);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    result = E__SUCCESS;
l_cleanup:

    return result;
}

static result_t
load_rules(const char *rules_path)
{
    result_t result = E__UNKNOWN;
    rule_table_t rule_table = {0};

    /* 1. Read human-rules file and convert to rule_table_t */
    result = RULE_TABLE_human_to_bin(&rule_table, rules_path);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 2. Write the rules list to the sysfs rules file */
    result = RULE_TABLE_write_bin(&rule_table, RULES_FILE_PATH);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    result = E__SUCCESS;
l_cleanup:

    return result;
}

static result_t
show_log(void)
{
    return LOGGING_print_logs(LOGS_PRINT_PATH);
}

static result_t
clear_log(void)
{
    return LOGGING_reset_logs(LOGS_CLEAR_PATH);
#if 0
    result_t result = E__UNKNOWN;
    FILE *f = NULL;
    char clear_command = LOGS_CLEAR_CMD_CHAR;
    size_t write_result = 0;

    /* 1. Open logs clear path */
    f = fopen(LOGS_CLEAR_PATH, "r");
    if (NULL == f) {
        perror("Can't open " LOGS_CLEAR_PATH);
        result = E__FOPEN_ERROR;
        goto l_cleanup;
    }

    /* 2. Write the clear command */
    write_result = fwrite(&clear_command, sizeof(clear_command), 1, f);
    if (1 > write_result) {
        (void)fprintf(stderr, "ERROR: writing to %s failed\n", LOGS_CLEAR_PATH);
        result = E__FWRITE_ERROR;
        goto l_cleanup;
    }
    /* Success */
    result = E__SUCCESS;
l_cleanup:

    FCLOSE_SAFE(f);

    return result;
#endif
}

int main(int argc, const char *argv[])
{
    int result = -1;

    /* 1. Arguments check */
    if (2 > argc) {
        (void)fprintf(stderr, "Usage: %s (show_rules|load_rules <path-to-rules-file>|show_log|clear_log)\n", argv[0]);
        result = 1;
        goto l_cleanup;
    }

    /* 2. Call the matching program */
    if (0 == strcmp(SHOW_RULES_STR, argv[1])) {
        result = show_rules();
    } else if (0 == strcmp(LOAD_RULES_STR, argv[1])) {
        if (3 != argc) {
            (void)fprintf(stderr, "Usage: %s load_rules <path-to-rules-file>\n", argv[0]);
        }
        result = load_rules(argv[2]);
    } else if (0 == strcmp(SHOW_LOG_STR, argv[1])) {
        result = show_log();
    } else if (0 == strcmp(CLEAR_LOG_STR, argv[1])) {
        result = clear_log();
    }
    if (E__SUCCESS != result) {
         goto l_cleanup;
    }

    result = 0;
l_cleanup:

    return result;
}

