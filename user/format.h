/**
 * @file format.h
 * @author Assaf Gadish
 *
 * @brief String format functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

#ifndef __FORMAT_H__
#define __FORMAT_H__

/*   I N C L U D E S    */
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "results.h"
#include "fw_user.h"


/*   M A C R O S   */
#define IP_ADDRESS_MAX (3 * 4 + 3 + 1)
#define IP_STRING_MAX (3 * 4 + 3 + 1 + 2 + 1)
#define PORT_STRING_MAX (5 + 1)
#define MAX_USER_PORT (1023)
#define GET_IP_MASK(n) ((0 == (n)) ? 0 : (~((1 << (32 - (n))) - 1)))
#define DATE_STRING_MAX_LENGTH (100)
#define REASON_STRING_MAX (30)
#define STATE_STRING_MAX (18)


/*   F U N C T I O N S   D E C L A R A T I O N S   */
void
FORMAT_ip_mask_pack(char *buffer,
                    size_t buffer_length,
                    uint32_t ip_big_endian,
                    uint8_t prefix_size);

result_t
FORMAT_ip_mask_unpack(char *ip_str,
                uint32_t *ip_out,
                uint32_t *prefix_mask_out,
                uint8_t *prefix_size_out);

void
FORMAT_port_to_str(char *buffer,
                   size_t buffer_length,
                   uint16_t port_big_endian);

result_t
FORMAT_port_to_bin(char *port_str,
                   uint16_t *port_out);

const char *
FORMAT_ack_to_str(ack_t ack);

const char *
FORMAT_action_to_str(uint8_t action);

const char *
FORMAT_protocol_to_str(prot_t protocol);

result_t
FORMAT_ack_to_bin(const char *ack_str, ack_t *ack_out);

result_t
FORMAT_action_to_bin(const char *action_str, uint8_t *action_out);

result_t
FORMAT_direction_to_bin(const char *direction_str, direction_t *direction_out);

prot_t
FORMAT_protocol_to_bin(const char *protocol_str);

const char *
FORMAT_direction_to_str(direction_t direction);

void
FORMAT_get_date_string(char *date, size_t buffer_length, unsigned long timestamp);

void
FORMAT_state_to_str(char *buffer,
                    size_t buffer_length,
                    uint8_t state);

void
FORMAT_ip_to_str(char *buffer,
                 size_t buffer_length,
                 uint32_t ip_big_endian);

void
FORMAT_reason_to_str(char *reason_str, size_t max_length, reason_t reason_code);


#endif /* __FORMAT_H__ */

