/**
 * @file connection_table.c
 * @author Assaf Gadish
 *
 * @brief Connection table functions
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

#include "connection_table.h"

/*   M A C R O S   */
#define CONN_BUFFER_COUNT (1)


/*   F U N C T I O N S    D E C L A R A T I O N S   */
static void
print_connection_title(void);

static void
print_connection(connection_table_entry_t *connection);


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
static void
print_connection_title(void)
{
    (void)printf("source		destination	state\n");
}

result_t
CONNECTION_TABLE_print_table(const char *read_conns_path)
{
    result_t result = E__UNKNOWN;
    int fd = INVALID_FD;
    connection_table_entry_t conns_buffer[CONN_BUFFER_COUNT] = {0};
    ssize_t read_result = -1;
    size_t conns_count = 0;
    size_t available_data = 0;
    size_t remaining_bytes = 0;
    size_t i = 0;

    if (NULL == read_conns_path) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Open rules file */
    errno = 0;
    fd = open(read_conns_path, O_RDONLY);
    if (INVALID_FD == fd) {
        perror("open error");
        result = E__OPEN_ERROR;
        goto l_cleanup;
    }

    /* 2. Print the title of the conns */
    print_connection_title();

    /* 3. Read conns until buffer is not full */
    do {
        /* 3.1. Read as many conns as we can */
        read_result = read(fd,
                           &conns_buffer[remaining_bytes],
                           sizeof(conns_buffer) - remaining_bytes);
        /* printf("%s: read(fd, buf, %d(=%d-%d)\n", __func__, sizeof(conns_buffer)-remaining_bytes, sizeof(conns_buffer), remaining_bytes); */
        if ((0 >= read_result) && (0 != errno)) {
            perror("read error");
            result = E__READ_ERROR;
            goto l_cleanup;
        }

        /* 3.2. Print all the complete conns */
        available_data = (size_t)read_result + remaining_bytes;
        conns_count = available_data / sizeof(conns_buffer[0]);

        for (i = 0 ; i < conns_count ; ++i) {
            print_connection(&conns_buffer[i]);
        }

        /* 3.3. Copy leftovers to the beginnig of the buffer
         *      Note: An overflow can't occur */
        remaining_bytes = available_data - (conns_count * sizeof(conns_buffer[0]));
        if (0 < conns_count) {
            (void)memcpy(&conns_buffer[0], &conns_buffer[conns_count], remaining_bytes);
        }
    } while (ARRAY_LENGTH(conns_buffer) == conns_count);

    /* 4. Check if all data is finished */
    if (0 < remaining_bytes) {
        (void)fprintf(stderr, "ERROR: Incomplete conns file\n");
        result = E__INCOMPLETE_CONN;
        goto l_cleanup;
    }

    result = E__SUCCESS;
l_cleanup:

    CLOSE_SAFE(fd);

    return result;
}

static void
print_connection(connection_table_entry_t *connection)
{
    char src_ip[IP_STRING_MAX] = {0};
    char dst_ip[IP_STRING_MAX] = {0};
    char src_port[PORT_STRING_MAX] = {0};
    char dst_port[PORT_STRING_MAX] = {0};
    char state[STATE_STRING_MAX] = {0};

    FORMAT_ip_to_str(src_ip, sizeof(src_ip), connection->id.src_ip);
    FORMAT_ip_to_str(dst_ip, sizeof(dst_ip), connection->id.dst_ip);
    FORMAT_port_to_str(src_port, sizeof(src_port), connection->id.src_port);
    FORMAT_port_to_str(dst_port, sizeof(dst_port), connection->id.dst_port);
    FORMAT_state_to_str(state, sizeof(state), connection->state);

    (void)printf("%s:%s\t%s:%s\t%s\n", src_ip, src_port, dst_ip, dst_port, state);
}

