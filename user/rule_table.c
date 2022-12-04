/**
 * @file rule_table.c
 * @author Assaf Gadish
 *
 * @brief Rule table functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S    */
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/user.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <stdlib.h>

#include "results.h"
#include "fw_user.h"
#include "common.h"
#include "format.h"

#include "rule_table.h"

/*   M A C R O S   */


/*   F U N C T I O N S    D E C L A R A T I O N S   */
static void
print_rule(rule_t *rule);

static result_t
parse_human_to_bin(FILE *file, rule_t *rule_out, bool_t *is_eof_out);


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
result_t
RULE_TABLE_bin_to_human(rule_table_t *rule_table, const char *path)
{
    result_t result = E__UNKNOWN;
    int fd = INVALID_FD;
    uint8_t rules_buffer[PAGE_SIZE] = {0};
    size_t rules_count = 0;
    ssize_t read_result = 0;

    /* 0. Input vaidation */
    if ((NULL == rule_table)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }
    /* 1. Open rules file */
    errno = 0;
    fd = open(path, O_RDONLY);
    if (INVALID_FD == fd) {
        perror("open error");
        result = E__OPEN_ERROR;
        goto l_cleanup;
    }

    /* 2. Read the rules page */
    read_result = read(fd, &rules_buffer, sizeof(rules_buffer));
    if ((0 >= read_result) && (0 != errno)) {
        perror("read error");
        result = E__READ_ERROR;
        goto l_cleanup;
    }

    /* 3. Verify size */
    /* 3.1. Check Rules overflow */
    if (read_result > (ssize_t)sizeof(rule_table->rules)) {
        (void)fprintf(stderr,
                      "ERROR: Got more than %lu bytes of  rules - got %lu\n",
                      (unsigned long)sizeof(rule_table->rules),
                      (unsigned long)read_result);
        result = E__BIN_RULES_OVERFLOW;
        goto l_cleanup;
    }

    /* 3.2. Align mismatch */
    rules_count = (size_t)read_result / sizeof(rule_table->rules[0]);
    if ((size_t)read_result != rules_count * sizeof(rule_table->rules[0])) {
        (void)fprintf(stderr, "ERROR: Bytes amount doesn't align to rules\n");
        result = E__BIN_RULES_ALIGN_MISMATCH;
        goto l_cleanup;
    }

    /* 4. Fill rule table */
    (void)memcpy((void *)rule_table->rules,
                 (void *)rules_buffer,
                 (size_t)read_result);

    rule_table->rules_count = rules_count;

    result = E__SUCCESS;
l_cleanup:

    CLOSE_SAFE(fd);
    return result;
}

static result_t
parse_human_to_bin(FILE *file, rule_t *rule_out, bool_t *is_eof_out)
{
    result_t result = E__UNKNOWN;
    int result_fscanf = -1;
    char name[20] = {0};
    char direction[4] = {0};
    char src_ip[IP_STRING_MAX] = {0};
    char dst_ip[IP_STRING_MAX] = {0};
    char protocol[5] = {0};
    char sport[6] = {0};
    char dport[6] = {0};
    char ack[4] = {0};
    char action[7] = {0};

    /* 1. Use fscanf to read variables from the file */
    result_fscanf = fscanf(
        file,
        "%s %s %s %s %s %s %s %s %s\n",
        name, direction, src_ip, dst_ip, protocol, sport, dport, ack, action
    );
    /* 2. Check if EOF */
    if (EOF == result_fscanf) {
        *is_eof_out = TRUE;
        result = E__SUCCESS;
        goto l_cleanup;
    }

    /* 3. Check if parsing failed */
    if (9 > result_fscanf) {
        (void)fprintf(stderr, "ERROR: Bad rules file format\n");
        result = E__HUMAN_RULES_FILE_INVALID;
        goto l_cleanup;
    }

    /* 4. Process IP addresses */
    /* 4.1. Source ip */
    result = FORMAT_ip_mask_unpack(src_ip,
                                &rule_out->src_ip,
                                &rule_out->src_prefix_mask,
                                &rule_out->src_prefix_size);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 4.2. Dest ip */
    result = FORMAT_ip_mask_unpack(dst_ip,
                                &rule_out->dst_ip,
                                &rule_out->dst_prefix_mask,
                                &rule_out->dst_prefix_size);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 5. Process ports */
    /* 4.2. Src port */
    result = FORMAT_port_to_bin(sport, &rule_out->src_port);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 4.2. Dst port */
    result = FORMAT_port_to_bin(dport, &rule_out->dst_port);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 6. Process ack */
    result = FORMAT_ack_to_bin(ack, &rule_out->ack);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 7. Process action */
    result = FORMAT_action_to_bin(action, &rule_out->action);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 8. Process direction */
    result = FORMAT_direction_to_bin(direction, &rule_out->direction);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 9. Process protocol */
    rule_out->protocol = FORMAT_protocol_to_bin(protocol);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 10. Copy rule name */
    (void)strncpy(rule_out->rule_name, name, ARRAY_LENGTH(rule_out->rule_name));

    *is_eof_out = FALSE;
    result = E__SUCCESS;
l_cleanup:

    return result;
}

result_t
RULE_TABLE_human_to_bin(rule_table_t *rule_table, const char *path)
{
    result_t result = E__UNKNOWN;
    FILE * file = NULL;
    bool_t is_eof = FALSE;
    size_t i = 0;

    /* 0. Input vaidation */
    if ((NULL == rule_table)) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Open human file */
    errno = 0;
    file = fopen(path, "r");
    if (NULL == file) {
        perror("fopen error");
        result = E__FOPEN_ERROR;
        goto l_cleanup;
    }

    /* 2. Parse rules up to the rules array */
    for (i = 0 ; i < ARRAY_LENGTH(rule_table->rules) ; ++i) {
        result = parse_human_to_bin(file, &rule_table->rules[i], &is_eof);
        if (E__SUCCESS != result) {
            goto l_cleanup;
        }

        if (is_eof) {
            break;
        }
    }

    /* 3. Check if we're out of rules */
    if (!is_eof) {
        (void)fprintf(stderr, "ERROR: rules file is too large\n");
        result = E__HUMAN_RULES_FILE_TOO_LARGE;
        goto l_cleanup;
    }

    /* 4. Fill the rules count */
    rule_table->rules_count = i;

    result = E__SUCCESS;
l_cleanup:

    FCLOSE_SAFE(file);
    return result;
}

result_t
RULE_TABLE_print_table(rule_table_t *rule_table)
{
    result_t result = E__UNKNOWN;
    size_t i = 0;

    if (NULL == rule_table) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    for (i = 0 ; i < rule_table->rules_count ; ++i) {
        print_rule(&rule_table->rules[i]);
    }

    result = E__SUCCESS;
l_cleanup:

    return result;
}

static void
print_rule(rule_t *rule)
{
    char src_ip[IP_STRING_MAX] = {0};
    char dst_ip[IP_STRING_MAX] = {0};
    char src_port[PORT_STRING_MAX] = {0};
    char dst_port[PORT_STRING_MAX] = {0};

    FORMAT_ip_mask_pack(src_ip, sizeof(src_ip), rule->src_ip, rule->src_prefix_size);
    FORMAT_ip_mask_pack(dst_ip, sizeof(dst_ip), rule->dst_ip, rule->dst_prefix_size);
    FORMAT_port_to_str(src_port, sizeof(src_port), rule->src_port);
    FORMAT_port_to_str(dst_port, sizeof(dst_port), rule->dst_port);

    (void)printf(
        "%.20s %s %s %s %s %s %s %s %s\n",
        rule->rule_name,
        FORMAT_direction_to_str(rule->direction),
        src_ip,
        dst_ip,
        FORMAT_protocol_to_str(rule->protocol),
        src_port,
        dst_port,
        FORMAT_ack_to_str(rule->ack),
        FORMAT_action_to_str(rule->action)
    );
}

result_t
RULE_TABLE_write_bin(rule_table_t *rule_table, const char *path)
{
    result_t result = E__UNKNOWN;
    int fd = INVALID_FD;
    ssize_t write_result = -1;
    size_t length_to_write = 0;

    /* 1. Open destination file */
    fd = open(path, O_WRONLY);
    if (INVALID_FD == fd) {
        perror("open error");
        result = E__OPEN_ERROR;
        goto l_cleanup;
    }

    /* 2. Write the rules */
    length_to_write = sizeof(rule_table->rules[0]) * rule_table->rules_count;
    write_result = write(fd, (void *)rule_table->rules, length_to_write);
    if (write_result < (ssize_t)length_to_write) {
        perror("write error");
        result = E__WRITE_ERROR;
        goto l_cleanup;
    }

    /* Success */
    result = E__SUCCESS;
l_cleanup:

    CLOSE_SAFE(fd);
    return result;
}

