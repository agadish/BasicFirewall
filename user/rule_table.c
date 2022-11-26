/**
 * @file results.h
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

#include "rule_table.h"

/*   M A C R O S   */
#define IP_ADDRESS_MAX (3 * 4 + 3 + 1)
#define IP_STRING_MAX (3 * 4 + 3 + 1 + 2 + 1)
#define PORT_STRING_MAX (5 + 1)
#define MAX_USER_PORT (1023)
#define GET_IP_MASK(n) (~((1 << (32 - (n))) - 1))


/*   F U N C T I O N S    D E C L A R A T I O N S   */
static void
print_rule(rule_t *rule);

static result_t
process_ip_mask(char *dst_ip,
                   uint32_t *dst_ip_out,
                   uint32_t *dst_prefix_mask_out,
                   uint8_t *dst_prefix_size_out);

#if 0
static void
fix_endianness(rule_table_t *rule_table);
#endif /* 0 */


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
result_t
RULE_TABLE_bin_to_human(const char *path, rule_table_t *rule_table_out)
{
    result_t result = E__UNKNOWN;
    int fd = INVALID_FD;
    uint8_t rules_buffer[PAGE_SIZE] = {0};
    size_t rules_count = 0;
    ssize_t read_result = 0;

    /* 0. Input vaidation */
    if ((NULL == rule_table_out)) {
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
    read_result = read(fd, rules_buffer, sizeof(rules_buffer));
    if ((0 >= read_result) && (0 != errno)) {
        perror("read error");
        result = E__READ_ERROR;
        goto l_cleanup;
    }

    /* 3. Verify size */
    rules_count = (size_t)read_result / sizeof(rule_table_out->rules[0]);

    /* 3.1. Rules overflow */
    if (rules_count > MAX_RULES) {
        (void)fprintf(stderr,
                      "ERROR: Got more than %lu (MAX_RULES) rules - got %lu\n",
                      (unsigned long)MAX_RULES,
                      (unsigned long)rules_count);
        result = E__BIN_RULES_OVERFLOW;
        goto l_cleanup;
    }

    /* 3.2. Align mismatch */
    if ((size_t)read_result != rules_count * sizeof(rule_table_out->rules[0])) {
        (void)fprintf(stderr, "ERROR: Bytes amount doesn't align to rules\n");
        result = E__BIN_RULES_ALIGN_MISMATCH;
        goto l_cleanup;
    }

    /* 4. Fill rule table */
    (void)memcpy((void *)rule_table_out->rules,
                 (void *)rules_buffer,
                 (size_t)read_result);


    rule_table_out->rules_count = rules_count;

#if 0
    /* 5. Fix endianness */
    fix_endianness(rule_table);
#endif /* 0 */

    result = E__SUCCESS;
l_cleanup:

    CLOSE_SAFE(fd);
    return result;
}

static result_t
process_port(char *port_str,
             uint16_t *port_out)
{
    result_t result = E__UNKNOWN;
    long result_atol = 0;
    uint16_t port = 0;

    /* 1. Check if is "any" */
    if (0 == strcmp(port_str, "any")) {
        port = 0;
    }

    /* 2. Check if is ">1023" */
    if (0 == strcmp(port_str, ">1023")) {
        port = 1023;
    }

    /* 3. Handle numeric value - verify it's correct */
    result_atol = atol(port_str);
    if (1023 <= result_atol) {
        (void)fprintf(stderr, "ERROR: Human rules file contains port >=1023. Must be\">1023\".\n");
        result = E__HUMAN_RULES_INVALID_PORT;
        goto l_cleanup;
    }
    port = (uint16_t)result_atol;

    *port_out = htons(port);
    result = E__SUCCESS;
l_cleanup:

    return result;
}

static result_t
process_ip_mask(char *ip_str,
                uint32_t *ip_out,
                uint32_t *prefix_mask_out,
                uint8_t *prefix_size_out)
{
    result_t result = E__UNKNOWN;
    char *separator_str = NULL;
    char *mask_string = NULL;
    struct in_addr ip_address = {0};
    int result_inet_pton = 0;

    /* 1. Check if is "any" */
    if (0 == strcmp(ip_str, "any")) {
        *ip_out = 0;
        *prefix_mask_out = 0;
        *prefix_size_out = 0;
    } else {

        /* 2. Find the '/' index which separates the IP and the mask */
        separator_str = strchr(ip_str, '/');
        if (NULL == separator_str) {
            (void)fprintf(
                stderr,
                "ERROR: Human rules file can't find '/' within an IP/Mask field\n"
            );
            result = E__HUMAN_RULES_FILE_INVALID_IP_MASK;
            goto l_cleanup;
        }

        /* 2. Replace the '/' with NULL-terminator and get two separate strings */
        separator_str[0] = '\x00';
        mask_string = &separator_str[1];

        /* 3. Process prefix mask/size */
        separator_str[0] = '\x00';
        *prefix_size_out = (uint32_t)atol(mask_string);
        /* Remark: IP mask is in network byte order */
        *prefix_mask_out = GET_IP_MASK(*prefix_size_out);

        /* 4. Process IP address */
        result_inet_pton = inet_pton(AF_INET, ip_str, &ip_address);
        if (1 != result_inet_pton) {
            perror("inet_pton error");
            result = E__INET_PTON_ERROR;
            goto l_cleanup;
        }
        *ip_out = htonl(ip_address.s_addr);
    }

    result = E__SUCCESS;
l_cleanup:

    return result;
}

static result_t
process_ack(const char *ack_str, ack_t *ack_out)
{
    result_t result = E__UNKNOWN;
    ack_t ack = ACK_ANY;

    if (0 == strcmp(ack_str, "yes")) {
        ack = ACK_YES;
    } else if (0 == strcmp(ack_str, "no")) {
        ack = ACK_NO;
    } else if (0 == strcmp(ack_str, "any")) {
        ack = ACK_ANY;
    } else {
        (void)fprintf(stderr, "ERROR: Human rules file contains invalid ack\n");
        result = E__HUMAN_RULES_INVALID_ACK;
        goto l_cleanup;
    }

    *ack_out = ack;
    result = E__SUCCESS;
l_cleanup:

    return result;
}

static result_t
process_action(const char *action_str, uint8_t *action_out)
{
    result_t result = E__UNKNOWN;
    uint8_t action = NF_ACCEPT;

    if (0 == strcmp(action_str, "accept")) {
        action = NF_ACCEPT;
    } else if (0 == strcmp(action_str, "drop")) {
        action = NF_DROP;
    } else {
        (void)fprintf(stderr, "ERROR: Human rules file contains invalid action\n");
        result = E__HUMAN_RULES_INVALID_ACTION;
        goto l_cleanup;
    }

    *action_out = action;
    result = E__SUCCESS;
l_cleanup:

    return result;
}

static result_t
parse_human_to_bin(FILE *file, rule_t *rule_out, bool_t *is_eof_out)
{
    result_t result = E__UNKNOWN;
    int result_fscanf = -1;
    char name[20] = {0};
    char iface[32] = {0};
    char src_ip[IP_STRING_MAX] = {0};
    char dst_ip[IP_STRING_MAX] = {0};
    char proto[5] = {0};
    char sport[6] = {0};
    char dport[6] = {0};
    char ack[4] = {0};
    char action[7] = {0};

    /* 1. Use fscanf to read variables from the file */
    result_fscanf = fscanf(
        file,
        "%s %s %s %s %s %s %s %s %s\n",
        name, iface, src_ip, dst_ip, proto, sport, dport, ack, action
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
    result = process_ip_mask(src_ip,
                                &rule_out->src_ip,
                                &rule_out->src_prefix_mask,
                                &rule_out->src_prefix_size);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 4.2. Dest ip */
    result = process_ip_mask(dst_ip,
                                &rule_out->dst_ip,
                                &rule_out->dst_prefix_mask,
                                &rule_out->dst_prefix_size);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 5. Process ports */
    /* 4.2. Src port */
    result = process_port(sport, &rule_out->src_port);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 4.2. Dst port */
    result = process_port(dport, &rule_out->dst_port);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 6. Process ack */
    result = process_ack(ack, &rule_out->ack);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 7. Process action */
    result = process_action(action, &rule_out->action);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }


    *is_eof_out = FALSE;
    result = E__SUCCESS;
l_cleanup:

    return result;
}

result_t
RULE_TABLE_human_to_bin(const char *path, rule_table_t *rule_table_out)
{
    result_t result = E__UNKNOWN;
    FILE * file = NULL;
    bool_t is_eof = FALSE;
    size_t i = 0;

    /* 0. Input vaidation */
    if ((NULL == rule_table_out)) {
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
    for (i = 0 ; i < ARRAY_LENGTH(rule_table_out->rules) ; ++i) {
        result = parse_human_to_bin(file, &rule_table_out->rules[i], &is_eof);
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
    rule_table_out->rules_count = i;

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

static inline const char *
direction_to_str(direction_t direction)
{
    const char *result = NULL;

    switch(direction)
    {
    case DIRECTION_IN:
        result = "in";
        break;
    case DIRECTION_OUT:
        result = "out";
        break;
    case DIRECTION_ANY:
        result = "any";
        break;
    default:
        result = "invalid";
        break;
    }

    return result;
}

static void
ip_to_str(char *buffer,
          size_t buffer_length,
          uint32_t ip_big_endian,
          uint8_t prefix_size)
{
    char ip_address[IP_ADDRESS_MAX] = {0};
    struct sockaddr_in sa = {0};
    const char * result_inet_ntop = NULL;
    
    /* 1. Convert IP address to string */
    result_inet_ntop = inet_ntop(AF_INET,
                                 &(sa.sin_addr),
                                 ip_address,
                                 INET_ADDRSTRLEN);
    /* 2. Print address */

    if (NULL == result_inet_ntop) {
        /* 2.1. Error converting? use "error" string */

        strncpy(buffer, "error", buffer_length);
    } else if (0 == prefix_size) {
        /* 2.2. Empty mask? use "any" string */
        strncpy(buffer, "any", buffer_length);
    } else {
        /* 2.3. Print the formatted string */
        (void)snprintf(buffer,
                       buffer_length,
                       "%s/%d",
                       ip_address,
                       prefix_size);
    }
}

static void
port_to_str(char *buffer,
            size_t buffer_length,
            uint16_t port_big_endian)
{
    uint16_t port = 0;
    
    port = ntohs(port_big_endian);
    if (MAX_USER_PORT < port) {
        strncpy(buffer, "any", buffer_length);
    } else {
        snprintf(buffer, buffer_length, "%d", (int)port);
    }
}

static const char *
ack_to_str(ack_t ack)
{
    const char * result = NULL;
    switch (ack)
    {
    case ACK_NO:
        result = "no";
        break;
    case ACK_YES:
        result = "yes";
        break;
    case ACK_ANY:
        result = "any";
        break;
    default:
        result = "error";
        break;
    }

    return result;
}

static const char *
action_to_str(uint8_t action)
{
    const char * result = NULL;
    switch (action)
    {
    case NF_ACCEPT:
        result = "accept";
        break;
    case NF_DROP:
        result = "drop";
        break;
    default:
        result = "error";
        break;
    }

    return result;
}

static const char *
protocol_to_str(prot_t protocol)
{
    const char * result = NULL;
    switch (protocol)
    {
    case PROT_ICMP:
        result = "icmp";
        break;
    case PROT_TCP:
        result = "tcp";
        break;
    case PROT_UDP:
        result = "udp";
        break;
    case PROT_OTHER:
        result = "other";
        break;
    case PROT_ANY:
        result = "any";
        break;
    default:
        result = "error";
        break;
    }

    return result;
}


static void
print_rule(rule_t *rule)
{
    char src_ip[IP_STRING_MAX] = {0};
    char dst_ip[IP_STRING_MAX] = {0};
    char src_port[PORT_STRING_MAX] = {0};
    char dst_port[PORT_STRING_MAX] = {0};

    ip_to_str(src_ip, sizeof(src_ip), rule->src_ip, rule->src_prefix_size);
    ip_to_str(dst_ip, sizeof(dst_ip), rule->dst_ip, rule->dst_prefix_size);
    port_to_str(src_port, sizeof(src_port), rule->src_port);
    port_to_str(dst_port, sizeof(dst_port), rule->dst_port);

    (void)printf(
        "%.20s %s %s %s %s %s %s %s %s\n",
        rule->rule_name,
        direction_to_str(rule->direction),
        src_ip,
        dst_ip,
        protocol_to_str(rule->protocol),
        src_port,
        dst_port,
        ack_to_str(rule->ack),
        action_to_str(rule->action)
    );
}


#if 0
    static void
fix_endianness(rule_table_t *rule_table)
{
    size_t i = 0;

    for (i = 0 ; i < rule_table->rule_count ; ++i) {
        rule_t *current_entry = &rule_table->rules[i];
        current_entry->src_ip = inet

    }
}
#endif /* 0 */
