/**
 * @file rule_table.c
 * @author Assaf Gadish
 *
 * @brief Rule table chaining and execution
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>

#include "fw.h"
#include "fw_log.h"
#include "common.h"
#include "net_utils.h"

#include "rule_table.h"


/*   M A C R O S   */
#define PORT_1023 (1023)
#define PORT_MORE_THAN_1023 (1024)
#define PORT_MORE_THAN_1023_N (ntohs(PORT_MORE_THAN_1023))



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
 * @brief Check if a rules array is valid
 * 
 * @param[in] rules The rules array
 * @param[in] rules_count Number of members in the array
 *
 * @return TRUE if valid, otherwise FALSE
 *
 * @see is_rule_valid
 */
static bool_t
are_rules_valid(const rule_t *rules, size_t rules_count);

/**
 * @brief Check if a rule is valid. For exact definition of valid, see source
 * 
 * @param[in] rule The rule to check
 *
 * @return TRUE if valid, otherwise FALSE
 *
 * @see is_rule_valid
 */
static bool_t
is_rule_valid(const rule_t *rule);


/*   F U N C T I O N S   I M P L E M E N T A T I O N S   */
void
RULE_TABLE_init(rule_table_t *table)
{
    if (NULL != table) {
        (void)memset(table, 0, sizeof(table));
    }
}

static bool_t
is_rule_valid(const rule_t *r)
{
    bool_t is_valid = FALSE;

    /* 1. Name */
    if (sizeof(r->rule_name) <= strnlen(r->rule_name, sizeof(r->rule_name))) {
        printk(KERN_INFO "Invalid rule: name is too long\n");
        goto l_cleanup;
    }

    /* 2. Direction */
    if (r->direction != ((r->direction) & DIRECTION_ANY)) {
        printk(KERN_INFO "Invalid rule: direction contains unknown flag\n");
        goto l_cleanup;
    }

    /* 3. Mask consistency */
    /* 3.1. Source */
    if (NET_UTILS_GET_IP_MASK(r->src_prefix_size) != r->src_prefix_mask) {
        printk(KERN_INFO
               "Invalid rule: src_prefix_size doesn't match src_prefix_mask\n");
        goto l_cleanup;
    }

    /* 3.1. Dst */
    if (NET_UTILS_GET_IP_MASK(r->dst_prefix_size) != r->dst_prefix_mask) {
        printk(KERN_INFO "Invalid rule: dst_prefix_size doesn't match dst_prefix_mask\n");
        goto l_cleanup;
    }

    /* 4. Ports larger than 1023 */
    /* 4.1. Src */
    if (ntohs(r->src_port) > PORT_MORE_THAN_1023) {
        printk(KERN_INFO "Invalid rule: src_port > 1023 must be %d\n",
                PORT_MORE_THAN_1023);
        goto l_cleanup;
    }

    /* 4.1. Dst */
    if (ntohs(r->dst_port) > PORT_MORE_THAN_1023) {
        printk(KERN_INFO "Invalid rule: dst_port > 1023 must be %d\n",
                PORT_MORE_THAN_1023);
        goto l_cleanup;
    }

    /* 5. Ack */
    if (r->ack != ((r->ack) & ACK_ANY)) {
        printk(KERN_INFO "Invalid rule: ack contains unknown flags\n");
        goto l_cleanup;
    }

    /* 6. Action */
    if ((NF_ACCEPT != r->action) && (NF_DROP != r->action)) {
        printk(KERN_INFO "Invalid rule: unknown action\n");
        goto l_cleanup;
    }

    is_valid = TRUE;
l_cleanup:

    return is_valid;
}

static bool_t
are_rules_valid(const rule_t *rules, size_t rules_count)
{
    bool_t are_valid = FALSE;
    size_t i = 0;

    for (i = 0 ; i < rules_count ; ++i) {
        if (FALSE == is_rule_valid(&rules[i])) {
            goto l_cleanup;
        }
    }

    are_valid = TRUE;
l_cleanup:

    return are_valid;
}

bool_t
RULE_TABLE_set_data(rule_table_t *table,
                    const uint8_t *data,
                    size_t data_length)
{
    bool_t result = FALSE;
    uint8_t rules_count = 0;

    /* 1. Calcualte rules_count */
    rules_count = data_length / sizeof(table->rules[0]);

    /* 2. Check if length is correct */
    /* 2.1. Complete rules */
    if (data_length != rules_count * sizeof(table->rules[0])) {
        printk(KERN_INFO \
            "%s: Rule table length isn't a multiple of sizeof(rule_t)=%lu\n",
            __func__,
            (unsigned long)sizeof(table->rules[0]));
        result = FALSE;
        goto l_cleanup;
    }
    /* 2.2. Doesn't override */
    if (sizeof((table->rules)) < data_length) {
        printk(KERN_INFO "%s: Rule table is too large\n", __func__);
        result = FALSE;
        goto l_cleanup;
    }

    /* 3. Validate rules */
    result = are_rules_valid((rule_t *)data, rules_count);
    if (FALSE == result) {
        goto l_cleanup;
    }

    /* 3. Copy rules */
    (void)memcpy(&table->rules, data, data_length);
    table->rules_count = rules_count;

    /* 4. Reset logs */
    FW_LOG_reset_logs();

    result = TRUE;

l_cleanup:

    if (TRUE != result) {
        RULE_TABLE_init(table);
    }

    return result;
}

bool_t
RULE_TABLE_dump_data(const rule_table_t *table,
                     uint8_t *buffer,
                     size_t *buffer_size_inout)
{
    bool_t result = FALSE;
    size_t required_length = 0;

    if ((NULL == table) || (NULL == buffer) || (NULL == buffer_size_inout)) {
        goto l_cleanup;
    }
    
    required_length = table->rules_count * sizeof(table->rules[0]);
    if (required_length > *buffer_size_inout) {
        goto l_cleanup;
    }

    (void)memcpy(buffer, &table->rules, required_length);
    *buffer_size_inout = required_length;

    result = TRUE;
l_cleanup:

    return result;
}

bool_t
RULE_TABLE_is_freepass(const rule_table_t *table,
                        const struct sk_buff *skb)
{
    bool_t is_freepass = FALSE;

    /* 0. Input validation */
    if ((NULL == table) || (NULL == skb)) {
        printk(KERN_WARNING "%s: invalid input\n", __func__);
        goto l_cleanup;
    }

    /* NOTE: forward chain shouldn't have loopback packets, but this is a
     *       requirement of the exercise */
    if ((!NET_UTILS_is_tcp_udp_icmp_packet(skb)) ||
        NET_UTILS_is_loopback_packet(skb))
    {
        is_freepass = TRUE;
    }

l_cleanup:

    return is_freepass;
}

bool_t
RULE_TABLE_check(const rule_table_t *table,
                 const struct sk_buff *skb,
                 __u8 *action_out,
                 reason_t *reason_out)
{
    bool_t does_match = FALSE;
    size_t i = 0;

    /* 0. Input validation */
    if ((NULL == table) ||
        (NULL == skb) ||
        (NULL == action_out) ||
        (NULL == reason_out))
    {
        printk(KERN_WARNING "RULE_TABLE_check got invalid input\n");
        goto l_cleanup;
    }

    if (0 == strncmp(skb->dev->name, DEBUG_INTERFACE, sizeof(skb->dev->name))) {
        printk(KERN_INFO "packet from debug interface, bye\n");
        does_match = TRUE;
        *action_out = NF_ACCEPT;
        *reason_out = -16;
    }

    /* 1. Go over the rules list */
    for (i = 0 ; i < table->rules_count ; ++i) {
        const rule_t * current_rule = &table->rules[i];

        /* 2. Check if the rule matches the packet  Go over the rules list */
        if (does_match_rule(current_rule, skb)) {
            /* 2.1. Found a matching rule */
            does_match = TRUE;

            /* 2.2. Return the rule's action,  and the rule id as the reason */
            *action_out = current_rule->action;
            *reason_out = (reason_t)i;

            /* 2.3. Finish the iteration over the rules list */
            break;
        }
    }
    
l_cleanup:

    return does_match;
}

static bool_t
does_match_rule(const rule_t *rule, const struct sk_buff *skb)
{
    bool_t does_match = FALSE;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    direction_t direction = DIRECTION_ANY;
    
    /* 1. Match soruce ip */
    if ((rule->src_ip & rule->src_prefix_mask) !=
            (ip_header->saddr & rule->src_prefix_mask)) {
        goto l_cleanup;
    }
    
    /* 2. Match destionation ip */
    if ((rule->dst_ip & rule->dst_prefix_mask) !=
            (ip_header->daddr & rule->dst_prefix_mask)) {
        goto l_cleanup;
    }

    /* 3. Match protocol */
    if ((PROT_ANY != rule->protocol) && 
        (ip_header->protocol != rule->protocol)) {
        goto l_cleanup;
    }

    /* 4. TCP specific */
    if (IPPROTO_TCP == ip_header->protocol) {
        struct tcphdr *tcp_header = (struct tcphdr *)skb_transport_header(skb);
        /* 4.1. Match src port */
        if ((0 != rule->src_port) &&
            (!((PORT_MORE_THAN_1023_N == rule->src_port) &&
               ntohs(tcp_header->source) > PORT_1023)) &&
            (rule->src_port != tcp_header->source))
        {

            goto l_cleanup;
        }

        /* 4.2. Match dst port */
        if ((0 != rule->dst_port) &&
            (!((PORT_MORE_THAN_1023_N == rule->dst_port) &&
               ntohs(tcp_header->dest) > PORT_1023)) &&
            (rule->dst_port != tcp_header->dest))
        {
            goto l_cleanup;
        }

        /* 4.3. TCP: match flags */
        if (!NET_UTILS_DOES_ACK_MATCH(tcp_header, rule)) {
            goto l_cleanup;
        }
    /* 5. UDP specific */
    } else if (IPPROTO_UDP == ip_header->protocol) {
        struct udphdr *udp_header = (struct udphdr *)skb_transport_header(skb);
        /* 4.1. Match src port */
        if ((0 != rule->src_port) &&
            (rule->src_port != udp_header->source) &&
            ((PORT_MORE_THAN_1023_N == rule->src_port) &&
             ntohs(udp_header->source) <= PORT_1023))
        {

            goto l_cleanup;
        }

        /* 4.2. Match dst port */
        if ((0 != rule->dst_port) &&
            (rule->dst_port != udp_header->dest) &&
            ((PORT_MORE_THAN_1023_N == rule->dst_port) &&
             ntohs(udp_header->dest) <= PORT_1023))
        {
            goto l_cleanup;
        }
    } /* Note: Nothing ICMP specific */

    /* 7. Match direction */
    direction = NET_UTILS_get_packet_direction(skb);
    /* Note: We will get no common bits for DIRECTION_UNKNOWN, or if the rule
     *       doesn't match the packet's direction */
    if (0 == (rule->direction & direction)) {
        goto l_cleanup;
    }

    /* 8. Haven't fallen yet? It's a match! */
    does_match = TRUE;
l_cleanup:

    return does_match;
}
