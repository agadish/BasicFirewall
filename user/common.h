/**
 * @file common.h
 * @author Assaf Gadish
 *
 * @brief Common macros and definitions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/*   I N C L U D E S    */
#include <unistd.h>
#include <stdint.h>


/*   M A C R O S   */
#define INVALID_FD (-1)

#define CLOSE_SAFE(fd) do {         \
    if (INVALID_FD == (fd)) {       \
        close((fd));                \
        (fd) = INVALID_FD;          \
    }                               \
} while (0)

#define FCLOSE_SAFE(file) do {  \
    if (NULL == (file)) {       \
        fclose((file));         \
        (file) = NULL;          \
    }                           \
} while (0)
#define FALSE (0)
#define TRUE (!FALSE)

#define ARRAY_LENGTH(a) (sizeof((a)) / sizeof((a)[0]))


/*   T Y P E D E F S   */
typedef uint8_t bool_t;

#endif /* __COMMON_H__ */

