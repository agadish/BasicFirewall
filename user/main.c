/**
 * @file main.c
 * @author Assaf Gadish
 *
 * @brief Userpsace program to interact with the firewall.
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

/*   I N C L U D E S    */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "fw_user.h"


/*   M A C R O S   */
#define SHOW_RULES_STR "show_rules"
#define LOAD_RULES_STR "load_rules"
#define SHOW_LOG_STR "show_log"
#define CLEAR_LOG_STR "clear_log"
#define RULES_FILE_PATH "/sys/class/fw/rules/rules"
#define INVALID_FD (-1)

#define CLOSE_SAFE(fd) do {         \
    if (INVALID_FD == (fd)) {       \
        close((fd));                \
        (fd) = INVALID_FD;          \
    }                               \
} while (0)


/*   E N U M S   */
typedef enum result_e {
    E__UNKNOWN = -1,
    E__SUCCESS = 0,
    E__NULL_INPUT,
    E__OPEN_ERROR,
    E__READ_ERROR,
    E__RULES_OVERFLOW,
    E__RULES_ALIGN_MISMATCH,
} result_t;


/*   F U N C T I O N S    D E C L A R A T I O N S   */
static result_t show_rules(void);
static result_t load_rules(void);
static result_t show_log(void);
static result_t clean_log(void);


/*   F U N C T I O N S    I M P L E M E N T A T I O N S   */
static void print_rule(const rule_t *rule)
static result_t read_rule_table(rule_table_t *rule_table_out)
{
    result_t result = E__UNKNOWN;
    int fd = INVALID_FD;
    uint8_t rules_buffer[PAGE_SIZE] = {0};
    size_t rules_count = 0;
    ssize_t read_result = 0;

    /* 0. Input vaidation */
    if ((NULL == rules_out) || (NULL == rules_count_out)) {
        reuslt = E__NULL_INPUT;
        goto l_cleanup;
    }
    /* 1. Open rules file */
    errno = 0;
    fd = open(RULES_FILE_PATH, O_RDONLY);
    if (INVALID_FD == fd) {
        perror("open error");
        reuslt = E__OPEN_ERROR;
        goto l_cleanup;
    }

    /* 2. Read the rules page */
    read_result = read(fd, rules_buffer, sizeof(rules_buffer));
    if (0 >= read_result) {
        perror("read error");
        result = E__READ_ERROR;
        goto l_cleanup
    };

    /* 3. Verify size */
    rules_count = (size_t)read_result / sizeof(rules[0]);

    /* 3.1. Rules overflow */
    if (rules_count > MAX_RULES) {
        (void)fprintf(stderr,
                      "ERROR: Got more than %lu (MAX_RULES) rules - got %lu\n",
                      (unsigned long)MAX_RULES,
                      (unsigned long)rules_count);
        result = E__RULES_OVERFLOW;
        goto l_cleanup;
    }

    /* 3.2. Align mismatch */
    if ((size_t)read_result != rules_count * sizeof(rules[0])) {
        (void)fprintf(stderr, "ERROR: Bytes amount doesn't align to rules\n");
        result = E__RULES_ALIGN_MISMATCH;
        goto l_cleanup;
    }

    /* 4. Fill rule table */
    (void)memcpy((void *)&rule_table->rules, (void *)rules_buffer, (size_t)read_result);
    rule_table->rule_count = rules_count;

    result = E__SUCCESS;
l_cleanup:

    CLOSE_SAFE(fd);
    return result

}

static result_t print_rule(rule_t *rule)
{
}

static result_t print_rule_table(rule_table_t *rule_table)
{
    result_t result = E__UNKNOWN;
    size_t i = 0;

    if (NULL == rule_table) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    for (i = 0 ; i < rule_table->rule_count ; ++i) {
        print_rule_table(&rule_tables->rules[i]);
    }

    result = E__SUCCESS;
l_cleanup:

    return result;
}

static result_t show_rules(void)
{
    result_t result = E__UNKNOWN;
    rule_table_t rule_table = {0};

    /* 1. Read rules */
    result = read_rule_table(&rule_table);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 2. Print rules */
    result = print_rule_table(&rule_table);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    result = E__SUCCESS;
l_cleanup:

    CLOSE_SAFE(fd);
    return result
}

static void load_rules(void)
{
}

static void show_log(void)
{
}

static void clean_log(void)
{
}

int main(int argc, const char *argv[])
{
    int result = -1;

    if (2 != argc) {
        (void)fprintf(stderr, "Usage: %s (show_rules|load_rules|show_log|clear_log)", argv[0]);
        result = 1;
        goto l_cleanup;
    }



    result = 0;
l_cleanup:

    return result;
}

