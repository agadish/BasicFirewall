/**
 * @file format.c
 * @author Assaf Gadish
 *
 * @brief String format functions
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
#include <time.h>

#include "format.h"
#include "fw_user.h"
#include "common.h"
#include "format.h"

#include "rule_table.h"

/*   M A C R O S   */


/*   F U N C T I O N S    D E C L A R A T I O N S   */

void
FORMAT_ip_mask_pack(char *buffer,
                    size_t buffer_length,
                    uint32_t ip_big_endian,
                    uint8_t prefix_size)
{
    char ip_address[IP_ADDRESS_MAX] = {0};
    struct sockaddr_in sa = {0};
    const char * result_inet_ntop = NULL;
    
    /* 1. Convert IP address to string */
    sa.sin_addr.s_addr = ip_big_endian;
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

void
FORMAT_port_to_str(char *buffer,
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

const char *
FORMAT_ack_to_str(ack_t ack)
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

const char *
FORMAT_reason_to_str(reason_t reason)
{
    const char * result = NULL;
    switch (reason)
    {
    case REASON_FW_INACTIVE:
        result = "REASON_FW_INACTIVE";
        break;
    case REASON_NO_MATCHING_RULE:
        result = "REASON_NO_MATCHING_RULE";
        break;
    case REASON_XMAS_PACKET:
        result = "REASON_XMAS_PACKET";
        break;
    case REASON_ILLEGAL_VALUE:
        result = "REASON_ILLEGAL_VALUE";
        break;
    default:
        result = "REASON_UNKNOWN";
        break;
    }

    return result;
}

const char *
FORMAT_action_to_str(uint8_t action)
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

const char *
FORMAT_protocol_to_str(prot_t protocol)
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

result_t
FORMAT_ip_mask_unpack(char *ip_str,
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
        *ip_out = ip_address.s_addr;
    }

    result = E__SUCCESS;
l_cleanup:

    return result;
}

result_t
FORMAT_ack_to_bin(const char *ack_str, ack_t *ack_out)
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

result_t
FORMAT_action_to_bin(const char *action_str, uint8_t *action_out)
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

result_t
FORMAT_direction_to_bin(const char *direction_str, direction_t *direction_out)
{
    result_t result = E__UNKNOWN;
    uint8_t direction = NF_ACCEPT;

    if (0 == strcmp(direction_str, "in")) {
        direction = DIRECTION_IN;
    } else if (0 == strcmp(direction_str, "out")) {
        direction = DIRECTION_OUT;
    } else if (0 == strcmp(direction_str, "any")) {
        direction = DIRECTION_ANY;
    } else {
        (void)fprintf(stderr, "ERROR: Human rules file contains invalid direction\n");
        result = E__HUMAN_RULES_INVALID_DIRECTION;
        goto l_cleanup;
    }

    *direction_out = direction;
    result = E__SUCCESS;
l_cleanup:

    return result;
}

prot_t
FORMAT_protocol_to_bin(const char *protocol_str)
{
    uint8_t protocol = NF_ACCEPT;

    if (0 == strcmp(protocol_str, "tcp")) {
        protocol = PROT_TCP;
    } else if (0 == strcmp(protocol_str, "udp")) {
        protocol = PROT_UDP;
    } else if (0 == strcmp(protocol_str, "icmp")) {
        protocol = PROT_ICMP;
    } else if (0 == strcmp(protocol_str, "any")) {
        protocol = PROT_ANY;
    } else {
        protocol = PROT_OTHER;
    }

    return protocol;
}

result_t
FORMAT_port_to_bin(char *port_str,
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

const char *
FORMAT_direction_to_str(direction_t direction)
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

void
FORMAT_get_date_string(char *date, size_t buffer_length)
{
    time_t now = 0;
    struct tm *t = NULL;
    int result_strftime = 0;

    now = time(NULL);
    t = localtime(&now);

    result_strftime = strftime(date, buffer_length - 1, "%d/%m/%Y %h:%M:%S", t);
    if (0 == result_strftime) {
        (void)strncpy(date, "UNKNOWN DATE", buffer_length);
    }
}


void
FORMAT_ip_to_str(char *buffer,
                 size_t buffer_length,
                 uint32_t ip_big_endian)
{
    char ip_address[IP_ADDRESS_MAX] = {0};
    struct sockaddr_in sa = {0};
    const char * result_inet_ntop = NULL;
    
    /* 1. Convert IP address to string */
    sa.sin_addr.s_addr = ip_big_endian;
    result_inet_ntop = inet_ntop(AF_INET,
                                 &(sa.sin_addr),
                                 ip_address,
                                 INET_ADDRSTRLEN);
    printf("0x%.8x -> \"%s\"\n", ip_big_endian, ip_address);
    /* 2. Copy IP to buffer */
    if (NULL == result_inet_ntop) {
        /* 2.1. Error converting? use "error" string */
        strncpy(buffer, "error", buffer_length);
    } else {
        strncpy(buffer, ip_address, buffer_length);
    }
}
