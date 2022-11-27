/**
 * @file results.h
 * @author Assaf Gadish
 *
 * @brief Return values for userapce program
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

#ifndef __RESULTS_H__
#define __RESULTS_H__

/*   E N U M S   */
typedef enum result_e {
    E__UNKNOWN = -1,
    E__SUCCESS = 0,
    E__NULL_INPUT,
    E__OPEN_ERROR,
    E__READ_ERROR,
    E__BIN_RULES_OVERFLOW,
    E__BIN_RULES_ALIGN_MISMATCH,
    E__HUMAN_RULES_FILE_TOO_LARGE,
    E__HUMAN_RULES_FILE_INVALID,
    E__FOPEN_ERROR,
    E__HUMAN_RULES_FILE_INVALID_IP_MASK,
    E__INET_PTON_ERROR,
    E__HUMAN_RULES_INVALID_PORT,
    E__HUMAN_RULES_INVALID_ACK,
    E__HUMAN_RULES_INVALID_ACTION,
    E__HUMAN_RULES_INVALID_DIRECTION,
    E__HUMAN_RULES_INVALID_PROTOCOL,
    E__WRITE_ERROR,
    E__INCOMPLETE_LOG,
} result_t;

#endif /* __RESULTS_H__ */

