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

#include "fw.h"
#include "common.h"
#include "fw_log.h"
#include "fw_results.h"


/*    M A C R O S   */
#define ROWS_PER_CHUNK (256)
#define CHUNK_AVAILABLE_SIZE (

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
 * @param[in] ctx The log dump context. Holds the current chunk's index, for
 *                fragmented read
 * @param[in] chunk The chunk to dump
 * @param[out] out_buffer The buffer to write to
 * @param[in] buffer_size Size of out_buffer
 *
 * @return Number of bytes that were copied (multiple of sizeof(log_row_t)
 *
 * @remark The function updates the given ctx. If the whole chunk was copied, it
 *         will be set as 0. Otherwise, will be increased with the number of
 *         chunks that were copied
 */
static size_t
dump_from_chunk(log_dump_context_t *ctx,
                logs_chunk_t *chunk,
                uint8_t *out_buffer,
                size_t buffer_size);


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
#if 0
    bool_t is_occupied = FALSE;

    /* 1. If no chunks are allocated, allocate the first chunk */
    if (NULL == g_logs_tail) {
        result = init_logs();
        if (E__SUCCESS != result) {
            goto l_cleanup; 
        }
    /* 2. If first chunk is allocated - check if it has space left */
    } else {
        is_occupied = (ROWS_PER_CHUNK == (g_logs_tail->write_index + 1));
        if (is_occupied) {
            /* 2.1. Allocate a new tail */
        }
    }
#endif /* 0 */



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

result_t
FW_LOG_log(const log_row_t *log)
{
    result_t result = E__UNKNOWN;
    log_row_t *dest_row = NULL;

    /* 1. Make sure we have a free slot at the logs chunk tail */
    result = allocate_new_chunk_if_required();
    if (E__SUCCESS != result) {
        goto l_cleanup;
    }

    /* 2. Perform the copy */
    dest_row = &(g_log_tail->rows[g_log_tail->write_index]);
    (void)memcpy(dest_row, log, sizeof(*log));

    /* 3. Increate logs count */
    ++(g_log_tail->write_index);

    result = E__SUCCESS;
l_cleanup:

    return result;
}

result_t
FW_LOG_init_dump_context(log_dump_context_t **context_out)
{
    result_t result = E__UNKNOWN;
    log_dump_context_t *ctx = NULL;

    /* 0. Input validation */
    if (NULL == context_out) {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Allocate context */
    ctx = (log_dump_context_t *)kmalloc(sizeof(*ctx), GFP_KERNEL);
    if (NULL == ctx) {
        result = E__KMALLOC_ERROR;
        goto l_cleanup;
    }

    /* 2. Init context */
    (void)memset(ctx, 0, sizeof(*ctx));

    /* Success */
    *context_out = ctx;
    result = E__SUCCESS;
l_cleanup:

    if (E__SUCCESS != result) {
        KFREE_SAFE(ctx);
        if (NULL != context_out) {
            *context_out = NULL;
        }
    }

    return result;
}

static size_t
dump_from_chunk(log_dump_context_t *ctx,
                logs_chunk_t *chunk,
                uint8_t *out_buffer,
                size_t buffer_size)
{
    /* 1. Calculate size to copy */
    size_t available_chunks_src = chunk->write_index - ctx->read_index;
    size_t available_chunks_dst = buffer_size / sizeof(log_row_t);
    size_t size_to_copy = sizeof(log_row_t) * min(available_chunks_src,
                                                  available_chunks_dst);

    /* 2. Perform the copy */
    (void)memcpy(out_buffer, &chunk->rows[ctx->read_index], size_to_copy);

    /* 3. Update the read index */
    /* 3.1. Hadn't enough space? increase read index */
    if (available_chunks_dst < available_chunks_src) {
        ctx->read_index += available_chunks_dst;
    /* 3.2. Everything was written - zero read index */
    } else {
        ctx->read_index = 0;
    }

    return size_to_copy;
}

result_t
FW_LOG_dump(log_dump_context_t *context,
            uint8_t *out_buffer,
            size_t buffer_size,
            size_t *bytes_written_out)
{
    result_t result = E__UNKNOWN;
    struct klist_iter i = {0};
    logs_chunk_t *current_entry = NULL;
    size_t total_written = 0;
    size_t current_written = 0;
    size_t remaining_size = buffer_size;

    /* 0. Input validation */
    if ((NULL == context) ||
        (NULL == out_buffer) ||
        (NULL == bytes_written_out))
    {
        result = E__NULL_INPUT;
        goto l_cleanup;
    }

    /* 1. Iterate over the logs chunks */
    klist_iter_init(&g_log, &i);
    while (remaining_size > 0) {
        /* 2. Get next chunk  */
        current_entry = (logs_chunk_t *)klist_next(&i); 
        /* 2.1. Last chunk? break */
        if (NULL == current_entry) {
            break;
        }

        /* 3. Copy as much available complete entires */
        current_written = dump_from_chunk(context,
                                          current_entry,
                                          &out_buffer[total_written],
                                          remaining_size);
        total_written += current_written;
        remaining_size -= current_written;
        
        /* 4. Can't fit even a single log_row_t? break */
        if (remaining_size < sizeof(log_row_t)) {
            break;
        }
    }

    /* 5. Finish iteration */
    klist_iter_exit(&i);
    *bytes_written_out = total_written;


    result = E__SUCCESS;
l_cleanup:

    return result;
}

void
FW_LOG_release_dump_context(log_dump_context_t *context)
{
    KFREE_SAFE(context);
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
}

