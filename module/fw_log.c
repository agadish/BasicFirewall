/**
 * @file fw_log.c
 * @author Assaf Gadish
 *
 * @brief Logging system of the firewall
 */
/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/list.h>

#include "fw.h"
#include "common.h"

#include "fw_log.h"

/*   M A C R O S   */
#define LOG_ROWS_PER_BUNCH (20)

/*   T Y P E D E F S    */
typedef struct fw_log_entry_s {
    struct klist entry;
    uint8_t no_rows;
    log_row_t rows[LOG_ROWS_PER_BUNCH];
} fw_log_bunch_t;


/*   G L O B A L S   */
LIST_HEAD_INIT(g_log_bunch_head);


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief Check whether a packet matches a rule
 * 
 * @param[in] rule The rule to check
 * @param[in] skb The packet to check
 *
 * @return TRUE if matches the rule, otherwise FALSE
 */
static bool_t
does_match_rule(const rule_t *rule, const struct sk_buff *skb);

/**
 * @brief Check if an inet packet has protocol TCP underlying
 * 
 * @param[in] skb
 *
 * @return TRUE if TCP packet, otherwise FALSE
 */
static bool_t
is_tcp_packet(const struct sk_buff *skb);


/**
 * @brief Determine if a packet has came
 * 
 * @param[in] skb The packet to check
 *
 * @return The direction of the packet. Note: If the packet neither comes from
 *         the IN or OUT interface, the function will return DIRECTION_UNKNOWN
 */
static direction_t
get_packet_direction(const struct sk_buff *skb);


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
void
RULE_TABLE_init(rule_table_t *table)
{
    if (NULL != table) {
        (void)memset(table, 0, sizeof(table));
    }
}

bool_t
RULE_TABLE_set_data(rule_table_t *table,
                    const uint8_t *data,
                    size_t data_length)
{
    bool_t result = FALSE;
    if (0 != data_length % sizeof(rule_t)) {
        result = FALSE;
        goto l_cleaup;
    }

    result = TRUE;
l_cleanup:

    if (TRUE != result) {
        RULE_TABLE_init_table);
    }

    return result;
}

bool_t
RULE_TABLE_check(const rule_table_t *table,
                 const struct sk_buff *skb,
                 __u8 *action_out)
{
    bool_t does_match = FALSE;
    size_t i = 0 ;

    if ((NULL == table) || (NULL == skb) || (NULL == action_out)) {
        printk(KERN_WARN "RULE_TABLE_check got invalid input\n");
        goto l_cleanup;
    }

    // 1. Check if UDP, ICMP or any non-TCP packet
    if (!is_tcp_packet(skb)) {
        goto l_cleanup;

    }

    // 2. Go over the rules list
    for (i = 0 ; i < table->rules_count ; ++i) {
        rule_t * current_rule = &table->rules[i];
        if (does_match_rule(current_tule, skb)) {
            // Found a match - break
            *action_out = current_rule->action;
            does_mach = TRUE;
            break;
        }
    }

l_cleanup:

    return does_match;
}

static bool_t
is_tcp_packet(const struct sk_buff *skb)
{
    struct iphdr * ip_header = (struct iphdr *)skb_network_header(skb);
    return (IPPROTO_TCP == ip_header->protocol) ? TRUE : FALSE;
}

static direction_t
get_packet_direction(const struct sk_buff *skb);
{
    direction_t direction = DIRECTION_ANY;
    char *iface_name = skb->dev->name;
    size_t name_length = ARRAY_SIZE(skb->dev->name);

    if (0 == strncmp(iface_name, IN_INTERFACE, array_size)) {
        direction = DIRECTION_IN;
    } else if (0 == strncmp(iface_name, OUT_INTERFACE, array_size)) {
        direction = DIRECTION_OUT;
    } else {
        DIRECTION_UNKNOWN;
    }

    return direction;
}

static bool_t
does_match_rule(const rule_t *rule, const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr * ip_header = (struct iphdr *)skb_network_header(skb);
    struct tcphdr * tcp_header = NULL;
    direction_t direction = DIRECTION_ANY;
    
    /* 1. Match soruce ip */
    if (rule->src_ip & rule->src_prefix_mask !=
            ip_header->saddr & rule->src_prefix_mask) {
        goto l_cleanup;
    }
    
    /* 2. Match destionation ip */
    if (rule->dst_ip & rule->dst_prefix_mask !=
            ip_header->saddr & rule->dst_prefix_mask) {
        goto l_cleanup;
    }

    /* 3. Match protocol */
    if (rule->protocol & ip_header->protocol !=
            ip_header->saddr & rule->dst_prefix_mask) {
        goto l_cleanup;
    }

    /* 4. Match flags */
    tcp_header = (struct tcphdr *)skb_transport_header(skb);
    if (!DOES_ACK_MATCH(tcp_header, rule)) {
        goto l_cleanup;
    }

    /* 5. Match src port */
    if ((0 != rule->src_port) &&
        (rule->src_port != tcp_header->source) &&
        ((1023 == rule->src_port) && tcp_header->source <= 1023))
    {
        goto l_cleaup;
    }

    /* 6. Match dst port */
    if ((0 != rule->dst_port) &&
        (rule->dst_port != tcp_header->dest) &&
        ((1023 == rule->dst_port) && tcp_header->dest <= 1023))
    {
        goto l_cleaup;
    }

    /* Note: this seems like the most complex test, and I assume most of the
     *       packets will fall on previous tests - so I left it to be last */
    /* 7. Match direction */
    direction = get_packet_direction(skb);
    /* Note: We will get no common bits for DIRECTION_UNKNOWN, or if the rule
     *       doesn't match the packet's direction */
    if (0 == rule->direction & direction) {
        goto l_cleanup;
    }

    /* 8. Haven't fallen yet? It's a match! */
    does_match = TRUE;
l_cleanup:

    return does_match;
}
