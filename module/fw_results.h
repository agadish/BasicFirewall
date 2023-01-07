/**
 * @file fw_results.h
 * @author Assaf Gadish
 *
 * @brief Return values for kernelsapce program
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

#ifndef __FW_RESULTS_H__
#define __FW_RESULTS_H__

/*   E N U M S   */
typedef enum result_e {
    E__UNKNOWN = -1,
    E__SUCCESS = 0,
    E__NULL_INPUT,
    E__KMALLOC_ERROR,
} result_t;


#endif /* __FW_RESULTS_H__ */

