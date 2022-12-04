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
#define ROWS_PER_CHUNK (2048)

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
 * @param[in] offset_in_chunk Offset within the chunk
 *
 * @return Number of bytes that were copied (multiple of sizeof(log_row_t)
 */
static size_t
dump_from_chunk(logs_chunk_t *chunk,
                uint8_t __user *out_buffer,
                size_t buffer_size,
                loff_t offset_in_chunk);

static void
init_log_row(log_row_t *row, const struct sk_buff *skb);

static void
touch_log_row(log_row_t *row, __u8 action, reason_t reason);

static log_row_t *
search_log_entry(const struct sk_buff *skb);

static bool_t
does_log_row_match(const log_row_t *row,
                   const struct sk_buff *skb);


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
        ((ROWS_PER_CHUNK - 1) <= g_log_tail->write_index))
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
dump_from_chunk(logs_chunk_t *chunk,
                uint8_t __user *out_buffer,
                size_t buffer_size,
                loff_t offset_in_chunk)
{
    /* 1. Calculate size to copy */
    size_t available_chunks_src = chunk->write_index - offset_in_chunk;
    size_t available_chunks_dst = buffer_size / sizeof(log_row_t);
    size_t size_to_copy = sizeof(log_row_t) * min(available_chunks_src,
                                                  available_chunks_dst);

    /* 2. Perform the copy */
    (void)copy_to_user(out_buffer, &chunk->rows[offset_in_chunk], size_to_copy);

    return size_to_copy;
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

    /* 0. Input validation */
    if ((NULL == out_buffer) ||
        (NULL == offset_inout))
    {
        goto l_cleanup;
    }

    /* 1. Iterate over the logs chunks */
    /* 1.1. Initialise offset */
    current_offset = *offset_inout;

    klist_iter_init(&g_log, &i);
    while (remaining_size > 0) {
        /* 2. Get next chunk  */
        current_entry = (logs_chunk_t *)klist_next(&i); 
        /* 2.1. Last chunk? break */
        if (NULL == current_entry) {
            break;
        }

        /* 3. Copy as much available complete entires */
        /* 3.1. Copy */
        current_written = dump_from_chunk(current_entry,
                                          &out_buffer[total_written],
                                          remaining_size,
                                          current_offset);
        /* 3.2. Update total, remaining and offset */
        total_written += current_written;
        remaining_size -= current_written;
        current_offset -= current_written;
        
        /* 4. Can't fit even a single log_row_t? break */
        if (remaining_size < sizeof(log_row_t)) {
            break;
        }
    }

    /* 5. Finish iteration */
    klist_iter_exit(&i);

    /* 6. Update offset */
    *offset_inout += (loff_t)total_written;

l_cleanup:

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

