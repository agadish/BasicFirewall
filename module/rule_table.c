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
#include "common.h"

#include "rule_table.h"


/*   M A C R O S   */
/**
 * @brief ack_t has 2 values: 0x1, 0x2, and their combination.
 *        We want to return FALSE for 0x1, and return TRUE for other values.
 *        XORing the ack bit with the ack_t value does the job
 */
#define DOES_ACK_MATCH(tcp_header, rule) (((tcp_header)->ack) ^ (rule)->ack)
#define IN_INTERFACE "enp0s8"
#define OUT_INTERFACE "enp0s9"
#define PORT_1023 (1023)
#define LOOPBACK_FIRST_TRIPLET_MASK (127 << 24)
#define IS_LOOPBACK_ADDRESS(a) (LOOPBACK_FIRST_TRIPLET_MASK == \
        ((a) & LOOPBACK_FIRST_TRIPLET_MASK))


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
 * @brief Check if an inet packet should be ignored (aka non TCP, UDP nor ICMP)
 * 
 * @param[in] skb
 *
 * @return TRUE if TCP/UDP/ICMP packet, otherwise FALSE
 */
static bool_t
is_tcp_udp_icmp_packet(const struct sk_buff *skb);

/**
 * @brief Check if a packet is loopback - source+destionation is 127.0.0.1/8
 * 
 * @param[in] skb
 *
 * @return TRUE if loopback packet, otherwise FALSE
 */
static bool_t
is_loopback_packet(const struct sk_buff *skb);

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
    uint8_t rules_count = 0;

    /* 1. Calcualte rules_count */
    rules_count = data_length / sizeof(table->rules[0]);

    /* 2. Check if length is correct */
    if (data_length != rules_count * sizeof(table->rules[0])) {
        result = FALSE;
        goto l_cleanup;
    }

    /* 3. Copy rules */
    // TODO: Verify
    (void)memcpy(table->rules, data, data_length);
    table->rules_count = rules_count;

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
RULE_TABLE_check(const rule_table_t *table,
                 const struct sk_buff *skb,
                 __u8 *action_out)
{
    bool_t does_match = FALSE;
    size_t i = 0 ;

    if ((NULL == table) || (NULL == skb) || (NULL == action_out)) {

        printk(KERN_WARNING "RULE_TABLE_check got invalid input\n");
        goto l_cleanup;
    }

    /* 1. Check if the packet has an handled protocol (TCP/UDP/ICMP) */
    if (!is_tcp_udp_icmp_packet(skb)) {
        *action_out = NF_ACCEPT;
        goto l_cleanup;

    }

    /* 2. Ignore loopback packets */
    /* NOTE: forward chain shouldn't have loopback packets, but this is a
     *       requirement of the exercise */
    if (!is_loopback_packet(skb)) {
        *action_out = NF_ACCEPT;
        goto l_cleanup;

    }

    /* 3. Go over the rules list */
    for (i = 0 ; i < table->rules_count ; ++i) {
        const rule_t * current_rule = &table->rules[i];

        if (does_match_rule(current_rule, skb)) {
            /* Found a match - break */
            *action_out = current_rule->action;

            does_match = TRUE;
            break;
        }
    }
    
    /* 4. No rule has matched? drop the packet */
    *action_out = NF_DROP;

l_cleanup:

    return does_match;
}

static bool_t
is_tcp_udp_icmp_packet(const struct sk_buff *skb)
{
    bool_t result = FALSE;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    if ((IPPROTO_TCP == ip_header->protocol) ||
        (IPPROTO_UDP == ip_header->protocol) ||
        (IPPROTO_ICMP == ip_header->protocol))
    {
        result = TRUE;
    }

    return result;
}

static bool_t
is_loopback_packet(const struct sk_buff *skb)
{
    bool_t result = FALSE;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    if (IS_LOOPBACK_ADDRESS(ip_header->saddr) && IS_LOOPBACK_ADDRESS(ip_header->daddr))
    {
        printk(KERN_INFO "found loopback packet\n");
        result = TRUE;
    }

    return result;
}

static direction_t
get_packet_direction(const struct sk_buff *skb)
{
    direction_t direction = DIRECTION_ANY;
    char *iface_name = skb->dev->name;
    size_t name_length = ARRAY_SIZE(skb->dev->name);

    if (0 == strncmp(iface_name, IN_INTERFACE, name_length)) {
        direction = DIRECTION_IN;
    } else if (0 == strncmp(iface_name, OUT_INTERFACE, name_length)) {
        direction = DIRECTION_OUT;
    } else {
        direction = DIRECTION_UNKNOWN;
    }

    return direction;
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

    /* [> 3. Match protocol <] */
    /* switch (rule->protocol) */
    /* { */
    /* case PROT_ICMP: */
    /* case PROT_TCP: */
    /* case PROT_UDP: */
    /*     if (rule->protocol != ip_header->protocol) { */
    /*         goto l_cleanup; */
    /*     } */
    /*     break; */
    /* case PROT_OTHER: */
    /*     switch (ip_header->protocol) */
    /*     { */
    /*         case PROT_ICMP: */
    /*         case PROT_TCP: */
    /*         case PROT_UDP: */
    /*             goto l_cleanup; */
    /*         default: */
    /*             break; */
    /*     } */
    /*     break; */
    /* deefault: */
    /*     break; */
    /* } */

    /* 4. TCP specific */
    if (IPPROTO_TCP == ip_header->protocol) {
        struct tcphdr *tcp_header = (struct tcphdr *)skb_transport_header(skb);
        /* 4.1. Match src port */
        if ((0 != rule->src_port) &&
            (rule->src_port != tcp_header->source) &&
            ((PORT_1023 == rule->src_port) && tcp_header->source <= PORT_1023))
        {

            goto l_cleanup;
        }

        /* 4.2. Match dst port */
        if ((0 != rule->dst_port) &&
            (rule->dst_port != tcp_header->dest) &&
            ((PORT_1023 == rule->dst_port) && tcp_header->dest <= PORT_1023))
        {

            goto l_cleanup;
        }

        /* 4.3. TCP: match flags */
        if (!DOES_ACK_MATCH(tcp_header, rule)) {
            goto l_cleanup;
        }
    /* 5. UDP specific */
    } else if (IPPROTO_UDP == ip_header->protocol) {
        struct udphdr *udp_header = (struct udphdr *)skb_transport_header(skb);
        /* 4.1. Match src port */
        if ((0 != rule->src_port) &&
            (rule->src_port != udp_header->source) &&
            ((PORT_1023 == rule->src_port) && udp_header->source <= PORT_1023))
        {

            goto l_cleanup;
        }

        /* 4.2. Match dst port */
        if ((0 != rule->dst_port) &&
            (rule->dst_port != udp_header->dest) &&
            ((PORT_1023 == rule->dst_port) && udp_header->dest <= PORT_1023))
        {

            goto l_cleanup;
        }
    } /* Note: Nothing ICMP specific */


    /* Note: this seems like the most complex test, and I assume most of the
     *       packets will fall on previous tests - so I left it to be last */
    /* 7. Match direction */
    direction = get_packet_direction(skb);
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
