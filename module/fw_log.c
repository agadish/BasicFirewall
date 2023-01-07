/**
 * @file fw_log.c
 * @author Assaf Gadish
 *
 * @brief Logging system of the firewall
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S   */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/klist.h>
#include <linux/time.h>

#include "fw.h"
#include "common.h"
#include "fw_log.h"
#include "fw_results.h"


/*    M A C R O S   */
#define ROWS_PER_CHUNK (2)

/*    T Y P E D E F S   */
struct log_dump_context_s {
    size_t read_index;
};

typedef struct logs_chunk_s {
    struct klist_node node;
    log_row_t rows[ROWS_PER_CHUNK];
    uint8_t write_index;
} logs_chunk_t;

typedef struct logs_list_s {
    struct klist list;
    logs_chunk_t *tail;
} logs_list_t;

/*   G L O B A L S   */
DEFINE_KLIST(g_log, NULL, NULL);
static logs_chunk_t *g_log_tail = NULL;


/*   F U N C T I O N S   D E C L A R A T I O N S   */
static result_t
create_logs_chunk(logs_chunk_t **chunk_out);

static result_t
allocate_new_chunk_if_required(void);

static result_t
add_tail(void);

/**
 * @brief Copy log_row_t's (as much as possible) from a given chunk to a buffer
 * 
 * @param[in] chunk The chunk to dump
 * @param[out] out_buffer The buffer to write to (userspace)
 * @param[in] buffer_size Size of out_buffer
 * @param[in] offset_to_start_inout Offset until start copying
 *
 * @return Number of bytes that were copied (multiple of sizeof(log_row_t)
 *
 * @remark *offset_to_start_inout must initially be less than chunk size
 */
static size_t
dump_from_chunk(logs_chunk_t *chunk,
                uint8_t __user *out_buffer,
                size_t buffer_size,
                loff_t *offset_to_start_inout);

static size_t
get_chunk_size(logs_chunk_t *chunk);

static void
init_log_row(log_row_t *row, const struct sk_buff *skb);

static void
touch_log_row(log_row_t *row, __u8 action, reason_t reason);

static log_row_t *
search_log_entry(const struct sk_buff *skb);

static bool_t
does_log_row_match(const log_row_t *row,
                   const struct sk_buff *skb);

/**
 * @brief Seek to the logs_chunk_t accordingly to the offset
 */
static logs_chunk_t *
seek_to_chunk(struct klist_iter *iter, loff_t *offset_inout);


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
static result_t
create_logs_chunk(logs_chunk_t **chunk_out)
{
    result_t result = E__UNKNOWN;
    logs_chunk_t *chunk = NULL;

    /* 1. Allocate list */
    chunk = (logs_chunk_t *)kmalloc(sizeof(*chunk), GFP_KERNEL);
    if (NULL == chunk) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    /* 2. Init list */
    (void)memset(chunk, 0, sizeof(*chunk));
    /* ??????? */
    INIT_LIST_HEAD(&chunk->node.n_node);

    /* Success */
    *chunk_out = chunk;
    result = E__SUCCESS;
l_cleanup:
    if (E__SUCCESS != result) {
        KFREE_SAFE(chunk);
    }

    return result;
}

static result_t
allocate_new_chunk_if_required(void)
{
    result_t result = E__UNKNOWN;

    if ((NULL == g_log_tail) ||
        (ROWS_PER_CHUNK <= g_log_tail->write_index))
    {
        result = add_tail();
        if (E__SUCCESS != result) {
            goto l_cleanup;
        }
    }

    result = E__SUCCESS;
l_cleanup:

    return result;
}

void
FW_LOG_init(void)
{
}

static result_t
add_tail(void)
{
    result_t result = E__UNKNOWN;

    logs_chunk_t *new_tail = NULL;

    /* 1. Allocate new chunk */
    result = create_logs_chunk(&new_tail);
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 2. Add the new chunk to the gloal tail */
    klist_add_tail(&new_tail->node, &g_log);

    /* 2.3. Update the latest tail pointer */
    g_log_tail = new_tail;

    result = E__SUCCESS;
l_cleanup:

    return result;
}

static void
init_log_row(log_row_t *row, const struct sk_buff *skb)
{
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    row->action = NF_DROP; /* Default */
    row->protocol = (unsigned char)ip_header->protocol;
    row->reason = REASON_FW_INACTIVE;
    row->count = 0;
    row->timestamp = 0;
    row->src_ip = ip_header->saddr;
    row->dst_ip = ip_header->daddr;

    switch (ip_header->protocol)
    {
    case IPPROTO_TCP:
        tcp_header = (struct tcphdr *)skb_transport_header(skb);
        row->src_port = tcp_header->source;
        row->dst_port = tcp_header->dest;
        break;
    case IPPROTO_UDP:
        udp_header = (struct udphdr *)skb_transport_header(skb);
        row->src_port = udp_header->source;
        row->dst_port = udp_header->dest;
        break;
    case IPPROTO_ICMP:
    default:
        row->src_port = 0;
        row->dst_port = 0;
        break;
    }
}

static void
touch_log_row(log_row_t *row, __u8 action, reason_t reason)
{
    struct timespec timespec = {0};

    getnstimeofday(&timespec);
    row->timestamp = timespec.tv_sec;
    row->reason = reason;
    row->action = action;
    ++(row->count);
}

static bool_t
does_log_row_match(const log_row_t *row,
                   const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    uint8_t protocol = ip_header->protocol;

    /* 1. Compare ip address (src+dest) and protocol */
    if ((row->src_ip != ip_header->saddr) ||
        (row->dst_ip != ip_header->daddr) ||
        (row->protocol != protocol))
    {
        goto l_cleanup;
    }

    /* 2. Compare ports */
    /* 2.1. TCP */
    if (IPPROTO_TCP == protocol)
    {
        struct tcphdr *tcp_header = (struct tcphdr *)skb_transport_header(skb);
        if ((row->src_port != tcp_header->source) ||
            (row->dst_port != tcp_header->dest))
        {
            goto l_cleanup;
        }
    /* 2.2. UDP */
    } else if (IPPROTO_UDP == protocol) {
        struct udphdr *udp_header = (struct udphdr *)skb_transport_header(skb);
        if ((row->src_port != udp_header->source) ||
            (row->dst_port != udp_header->dest))
        {
            goto l_cleanup;
        }
    /* 2.3. ICMP */
    } else if (IPPROTO_ICMP == protocol) {
        /* Nothing to check */
    /* 2.4. Unkwnown protocol */
    } else {
        goto l_cleanup;
    }

    does_match = TRUE;
l_cleanup:

    return does_match;
}

static log_row_t *
search_log_entry(const struct sk_buff *skb)
{
    log_row_t *row = NULL;
    struct klist_iter list_iter = {0};
    logs_chunk_t *current_entry = NULL;
    uint8_t i = 0;

    klist_iter_init(&g_log, &list_iter);

    while (TRUE) {
        /* 1. Get next chunk  */
        current_entry = (logs_chunk_t *)klist_next(&list_iter); 
        /* 2. Last chunk? break */
        if (NULL == current_entry) {
            break;
        }

        /* 3. Iterate rows in chunk */
        for (i = 0 ; i < current_entry->write_index ; ++i) {
            log_row_t *current_row = &current_entry->rows[i];
            /* 3.1. Check if row matches the rule */
            if (does_log_row_match(current_row, skb)) {
                row = current_row;
                break;
            }
        }
    }

    klist_iter_exit(&list_iter);

    return row;
}

result_t
FW_LOG_log_match(const struct sk_buff *skb, 
                 __u8 action,
                 reason_t reason)
{
    result_t result = E__UNKNOWN;
    log_row_t *dest_row = NULL;

    /* 1. Get the row for this log */
    dest_row = search_log_entry(skb);
    if (NULL == dest_row) {
        /* 1. Get a poiner to the matching log_row_t */
        /* 1.1. Make sure we have a free slot at the logs chunk tail */
        result = allocate_new_chunk_if_required();
        if (E__SUCCESS != result) {
            goto l_cleanup;
        }

        /* 1.2. Choose the last row */
        dest_row = &(g_log_tail->rows[g_log_tail->write_index]);

        /* 1.3. Initialize the log row */
        init_log_row(dest_row, skb);

        /* 1.4. Increate logs count */
        ++(g_log_tail->write_index);
    }

    /* 2. Touch the row - increase the counter, and update the timestamp */
    touch_log_row(dest_row, action, reason);


    result = E__SUCCESS;
l_cleanup:

    return result;
}

static size_t
get_chunk_size(logs_chunk_t *chunk)
{
    size_t available_source_bytes = sizeof(log_row_t) * chunk->write_index;
    return available_source_bytes;
}

static size_t
dump_from_chunk(logs_chunk_t *chunk,
                uint8_t __user *out_buffer,
                size_t buffer_size,
                loff_t *offset_to_start_inout)
{
    /* 1. Calculate size to copy */
    size_t available_source_bytes = 0;
    size_t size_to_copy = 0;

    /* 1. Calculate size to copy */
    available_source_bytes = ((sizeof(log_row_t) * chunk->write_index) -
                              (size_t)(*offset_to_start_inout));

    /* 2. Determine how bytes to copy */
    size_to_copy = min(buffer_size, available_source_bytes);


    /* 3. Copy */
    (void)copy_to_user(
        out_buffer,
        &((uint8_t *)&(chunk->rows))[(size_t)*offset_to_start_inout],
        size_to_copy
    );

    /* 4. Update offset parameter - was chunk done? */
    if (available_source_bytes < size_to_copy) {
        *offset_to_start_inout += (loff_t)size_to_copy;
    } else {
        *offset_to_start_inout = 0;
    }


    return size_to_copy;
}

static logs_chunk_t *
seek_to_chunk(struct klist_iter *iter, loff_t *offset_inout)
{
    logs_chunk_t *result = NULL;
    logs_chunk_t *current_chunk = NULL;
    size_t current_chunk_size = 0;

    while (TRUE) {
        /* 1. Get a chunk */
        current_chunk = (logs_chunk_t *)klist_next(iter); 
        if (NULL == current_chunk) {
            /* 1.1. No more chunks? return NULL */
            goto l_cleanup;
        }

        /* 2. Decrease chunk size */
        current_chunk_size = get_chunk_size(current_chunk);
        /* 2.1. If offset is less than chunk, this is the destination chunk */
        if (current_chunk_size > (size_t)*offset_inout) {
            result = current_chunk;
            break;
        } else {
            *offset_inout -= (loff_t)current_chunk_size;
        }
    }

l_cleanup:
    return current_chunk;
}

size_t
FW_LOG_dump(uint8_t __user *out_buffer,
            size_t buffer_size,
            loff_t *offset_inout)
{
    struct klist_iter i = {0};
    logs_chunk_t *current_entry = NULL;
    size_t total_written = 0;
    size_t current_written = 0;
    size_t remaining_size = buffer_size;
    loff_t current_offset = 0;
    bool_t is_iterating = FALSE;

    /* 0. Input validation */
    if ((NULL == out_buffer) ||
        (NULL == offset_inout))
    {
        goto l_cleanup;
    }

    /* 1. Init */
    current_offset = *offset_inout;
    klist_iter_init(&g_log, &i);
    is_iterating = TRUE;

    /* 2. Get the first chunk accordingly to the given offset */
    current_entry = seek_to_chunk(&i, &current_offset);
    /* Remark: may be NULL! */

    /* 3. Copy available data */
    for (;
         NULL != current_entry ;
         current_entry = (logs_chunk_t *)klist_next(&i))
    {
        /* 3.1. Copy as much available complete entires */
        current_written = dump_from_chunk(current_entry,
                                          &out_buffer[total_written],
                                          remaining_size,
                                          &current_offset);
        /* 3.2. Update total, remaining and offset */
        total_written += current_written;
        remaining_size -= current_written;
        
        /* 3.3. Can't fit even a single log_row_t? break */
        if (remaining_size < sizeof(log_row_t)) {
            break;
        }
    }

    /* 6. Update offset */
    *offset_inout += (loff_t)total_written;

l_cleanup:
    if (is_iterating) {
        klist_iter_exit(&i);
        is_iterating = FALSE;
    }

    return total_written;
}

void
FW_LOG_shutdown(void)
{
    FW_LOG_reset_logs();
}

void
FW_LOG_reset_logs(void)
{
    struct klist_iter i = {0};
    logs_chunk_t *current_entry = NULL;
    logs_chunk_t *next_entry = NULL;

    klist_iter_init(&g_log, &i);
    current_entry = (logs_chunk_t *)klist_next(&i); 

    while (NULL != current_entry) {
        next_entry = (logs_chunk_t *)klist_next(&i);
        klist_del(&current_entry->node);
        KFREE_SAFE(current_entry);
        current_entry = next_entry;
    }

    g_log_tail = NULL;
    klist_iter_exit(&i);
}

