/**
 * @file net_utils.c
 * @author Assaf Gadish
 *
 * @brief sk_buff helper functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */

/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

#include "common.h"
#include "fw.h"
#include "net_utils.h"


/*   M A C R O S   */
#define LO_INTERFACE "lo"


/*   F U N C T I O N S    I M P L E M E N T A T I O N S   */
bool_t
NET_UTILS_fix_checksum(struct sk_buff *skb)
{
    bool_t was_fixed = FALSE;
    uint16_t tcplen = 0;
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = tcp_hdr(skb);

    if (NULL == skb) {
        was_fixed = TRUE;
        goto l_cleanup;
    }
    
    /* Fix IP header checksum */
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

    /*
     * From Linux doc here: https://elixir.bootlin.com/linux/v4.15/source/include/linux/skbuff.h#L90
     * CHECKSUM_NONE:
     *
     *   Device did not checksum this packet e.g. due to lack of capabilities.
     *   The packet contains full (though not verified) checksum in packet but
     *   not in skb->csum. Thus, skb->csum is undefined in this case.
     */
    skb->ip_summed = CHECKSUM_NONE;
    skb->csum_valid = 0;

    /* Linearize the skb */
    if (skb_linearize(skb) < 0) {
        was_fixed = TRUE;
        goto l_cleanup;
   }

    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    /* Fix TCP header checksum */
    tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));

l_cleanup:

    return was_fixed;
}

uint32_t
NET_UTILS_get_local_ip__network_order(struct net_device *dev)
{
    uint32_t result = 0;
    struct in_device *in_dev = NULL;
    struct in_ifaddr *ifa = NULL;

    if (NULL == dev) {
        result = 0;
        goto l_cleanup;
    }

    in_dev = (struct in_device *)dev->ip_ptr;
    if (NULL != in_dev) {
        ifa = in_dev->ifa_list;
        if (NULL != ifa) {
            result = ifa->ifa_address;
        } else {
            printk(KERN_ERR "%s: device doesn't have an IP\n", __func__);
        }
    } else {
        printk(KERN_ERR "%s: device doesn't have an IP\n", __func__);
    }


l_cleanup:

    return result;
}

bool_t
NET_UTILS_is_syn_packet(const struct tcphdr *tcp_header)
{
    bool_t is_syn_packet = FALSE;

    if (NULL != tcp_header) {
        is_syn_packet = (0 == tcp_header->ack) ? TRUE : FALSE;
    }

    return is_syn_packet;
}

direction_t
NET_UTILS_get_packet_direction(const struct sk_buff *skb)
{
    direction_t direction = DIRECTION_ANY;
    char *iface_name = skb->dev->name;
    size_t name_length = ARRAY_SIZE(skb->dev->name);

    if (NULL == skb) {
        direction = DIRECTION_UNKNOWN;
        goto l_cleanup;
    }

    if (NULL == iface_name) {
        /* Localhost */
        direction = DIRECTION_ANY; 
        goto l_cleanup;
    }

    if (0 == strncmp(iface_name, IN_INTERFACE, name_length)) {
        direction = DIRECTION_IN;
    } else if (0 == strncmp(iface_name, OUT_INTERFACE, name_length)) {
        direction = DIRECTION_OUT;
    } else {
        /* printk(KERN_INFO "direction UNKNOWN: got %s\n", iface_name); */
        direction = DIRECTION_UNKNOWN;
    }

l_cleanup:

    return direction;
}

bool_t
NET_UTILS_is_tcp_udp_icmp_packet(const struct sk_buff *skb)
{
    bool_t result = FALSE;
    struct iphdr *ip_header = NULL;

    if (NULL == skb) {
        goto l_cleanup;
    }

    ip_header = (struct iphdr *)skb_network_header(skb);
    if ((IPPROTO_TCP == ip_header->protocol) ||
        (IPPROTO_UDP == ip_header->protocol) ||
        (IPPROTO_ICMP == ip_header->protocol))
    {
        result = TRUE;
    }

l_cleanup:

    return result;
}

bool_t
NET_UTILS_is_loopback_packet(const struct sk_buff *skb)
{
    bool_t result = FALSE;
    char *iface_name = skb->dev->name;
    size_t name_length = ARRAY_SIZE(skb->dev->name);

    if (NULL == skb) {
        goto l_cleanup;
    }

    if (0 == strncmp(iface_name, LO_INTERFACE, name_length)) {
        result = TRUE;
    }

l_cleanup:

    return result;
}

bool_t
NET_UTILS_is_xmas_packet(const struct sk_buff *skb)
{
    bool_t result = FALSE;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;

    /* 0. Input validation */
    if (NULL == skb) {
        goto l_cleanup;
    }

    /* 1. Check if TCP */
    ip_header = (struct iphdr *)skb_network_header(skb);
    if (IPPROTO_TCP != ip_header->protocol) { 
        goto l_cleanup;
    }

    tcp_header = (struct tcphdr *)skb_transport_header(skb);
    result = NET_UTILS_IS_XMAS_TCP_HEADER(tcp_header);

l_cleanup:

    return result;
}

