/**
 * @file common.h
 * @author Assaf Gadish
 *
 * @brief Common macros and typedefs
 */
#ifndef __COMMON_H__
#define __COMMON_H__

/*   I N C L U D E S   */
#include <linux/types.h>


/*   M A C R O S   */
#define UNUSED_ARG(a) ((void)(a))
#define FALSE (0)
#define TRUE (!FALSE)

#define KFREE_SAFE(p) do {  \
    if (NULL != (p)) {      \
        kfree((p));         \
        (p) = NULL;         \
    }                       \
} while (0)


/*   T Y P E D E F S    */
typedef uint8_t bool_t;


#endif /* __COMMON_H__ */
