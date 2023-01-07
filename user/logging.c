/**
 * @file logging.c
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

#include "logging.h"

/*   M A C R O S   */
#define LOG_BUFFER_COUNT (4)
#define LOGS_CLEAR_CMD_CHAR ('0')


/*   F U N C T I O N S    D E C L A R A T I O N S   */
static void
print_log_title(void);

static void
print_log_row(log_row_t *log_row);


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
static void
print_log_title(void)
{
    (void)printf("timestamp		src_ip		dst_ip		src_port	dst_port	"
                 "protocol	action	reason		count\n");
}

static void
print_log_row(log_row_t *row)
{
    char date[DATE_STRING_MAX_LENGTH] = {0};
    char src_ip[IP_STRING_MAX] = {0};
    char dst_ip[IP_STRING_MAX] = {0};
    char reason[REASON_STRING_MAX] = {0};
    uint16_t src_port = 0;
    uint16_t dst_port = 0;


    FORMAT_get_date_string(date, ARRAY_LENGTH(date), row->timestamp);
    FORMAT_ip_to_str(src_ip, sizeof(src_ip), row->src_ip);
    FORMAT_ip_to_str(dst_ip, sizeof(dst_ip), row->dst_ip);
    src_port = ntohs(row->src_port);
    dst_port = ntohs(row->dst_port);
    FORMAT_reason_to_str(reason, sizeof(reason), row->reason);

    (void)printf("%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%lu\n",
            date,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            FORMAT_protocol_to_str(row->protocol),
            FORMAT_action_to_str(row->action),
            reason,
            (unsigned long)row->count);
}

result_t
LOGGING_print_logs(const char *read_logs_path)
{
    result_t result = E__UNKNOWN;
    int fd = INVALID_FD;
    log_row_t logs_buffer[LOG_BUFFER_COUNT] = {0};
    ssize_t read_result = -1;
    size_t logs_count = 0;
    size_t available_data = 0;
    size_t remaining_bytes = 0;
    size_t i = 0;

    if (NULL == read_logs_path) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Open rules file */
    errno = 0;
    fd = open(read_logs_path, O_RDONLY);
    if (INVALID_FD == fd) {
        perror("open error");
        result = E__OPEN_ERROR;
        goto l_cleanup;
    }

    /* 2. Print the title of the logs */
    print_log_title();

    /* 3. Read logs until buffer is not full */
    do {
        /* 3.1. Read as many logs as we can */
        read_result = read(fd,
                           &logs_buffer[remaining_bytes],
                           sizeof(logs_buffer) - remaining_bytes);
        /* printf("%s: read(fd, buf, %d(=%d-%d)\n", __func__, sizeof(logs_buffer)-remaining_bytes, sizeof(logs_buffer), remaining_bytes); */
        if ((0 >= read_result) && (0 != errno)) {
            perror("read error");
            result = E__READ_ERROR;
            goto l_cleanup;
        }

        /* 3.2. Print all the complete logs */
        available_data = (size_t)read_result + remaining_bytes;
        logs_count = available_data / sizeof(logs_buffer[0]);

        for (i = 0 ; i < logs_count ; ++i) {
            print_log_row(&logs_buffer[i]);
        }

        /* 3.3. Copy leftovers to the beginnig of the buffer
         *      Note: An overflow can't occur */
        remaining_bytes = available_data - (logs_count * sizeof(logs_buffer[0]));
        if (0 < logs_count) {
            (void)memcpy(&logs_buffer[0], &logs_buffer[logs_count], remaining_bytes);
        }
    } while (ARRAY_LENGTH(logs_buffer) == logs_count);

    /* 4. Check if all data is finished */
    if (0 < remaining_bytes) {
        (void)fprintf(stderr, "ERROR: Incomplete logs file\n");
        result = E__INCOMPLETE_LOG;
        goto l_cleanup;
    }

    result = E__SUCCESS;
l_cleanup:

    CLOSE_SAFE(fd);

    return result;
}

result_t
LOGGING_reset_logs(const char *reset_logs_path)
{
    result_t result = E__UNKNOWN;
    int fd = INVALID_FD;
    ssize_t write_result = -1;
    uint8_t write_data[] = {LOGS_CLEAR_CMD_CHAR};

    /* 0. Input validation */
    if (NULL == reset_logs_path) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Open destination file */
    fd = open(reset_logs_path, O_WRONLY);
    if (INVALID_FD == fd) {
        perror("open error");
        result = E__OPEN_ERROR;
        goto l_cleanup;
    }

    /* 2. Write reset */
    write_result = write(fd, (void *)&write_data, sizeof(write_data));
    if (write_result < (ssize_t)sizeof(write_data)) {
        perror("write error");
        result = E__WRITE_ERROR;
        goto l_cleanup;
    }

    result = E__SUCCESS;
l_cleanup:

    CLOSE_SAFE(fd);

    return result;
}
