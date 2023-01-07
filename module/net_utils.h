/**
 * @file net_utils.h
 * @author Assaf Gadish
 *
 * @brief sk_buff helper functions
 *        Written for course "Workshop in Information Security", TAU 2022-23.
 */
#ifndef __NET_UTILS_H__
#define __NET_UTILS_H__

/*   I N C L U D E S   */
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/tcp.h>

#include "common.h"
#include "fw.h"


/*   C O N S T A N T S   */
#define IN_INTERFACE "enp0s8"
#define OUT_INTERFACE "enp0s9"
#define DEBUG_INTERFACE "enp0s3"


/*   M A C R O S   */
/**
 * @brief ack_t has 2 values: 0x1, 0x2, and their combination.
 *        We want to return FALSE for 0x1, and return TRUE for other values.
 *        XORing the ack bit with the ack_t value does the job
 */
#define NET_UTILS_DOES_ACK_MATCH(tcp_header, rule) (((tcp_header)->ack) ^ \
                                                    (rule)->ack)

#define NET_UTILS_GET_IP_MASK(n) ((0 == (n)) ? 0 : (~((1 << (32 - (n))) - 1)))
#define NET_UTILS_is_tcp_packet(skb) (                              \
    (NULL != (skb)) && (IPPROTO_TCP == ip_hdr((skb))->protocol)     \
)


/*   F U N C T I O N S   D E C L A R A T I O N S   */
/**
 * @brief Determine if a packet is a TCP-SYN pack-SYN packet.
 *        The test (as specificied on the exercise), actually checks if the
 *        packet doesn't have the ACK flag.
 * 
 * @param[in] tcp_header The TCP header of the packet
 *
 * @return TRUE if SYN packet, otherwise FALSE
 */
bool_t
NET_UTILS_is_syn_packet(const struct sk_buff *skb);

/**
 * @brief Recalculate the IP checksum and the TCP checksum
 * 
 * @param[in] skb Packet to recalcualte it checksums
 *
 * @return TRUE if was fixed, FALSE if NULL is given or upon linearization error
 *
 * @author https://www.github.com/reuvenpl/checksum
 *
 */
bool_t
NET_UTILS_fix_checksums(struct sk_buff *skb);

/**
 * @brief Get the local IP address of the given network device, or 0 on error.
 *        The returned address in on big endian
 *
 * @param[in] dev The device to get its address
 *
 * @return The given IP address, or 0 on error
 */
uint32_t
NET_UTILS_get_local_ip__network_order(struct net_device *dev);

/**
 * @brief Determine whether a packet has arrived through IN_INTERFACE or
 *        OUT_INTERFACE
 * 
 * @param[in] skb The packet to check
 *
 * @return The direction of the packet. Note: If the packet neither comes from
 *         the IN or OUT interface, the function will return DIRECTION_UNKNOWN
 */
direction_t
NET_UTILS_get_packet_direction(const struct sk_buff *skb);

/**
 * @brief Check if a packet is loopback - source+destionation is 127.0.0.1/8
 * 
 * @param[in] skb
 *
 * @return TRUE if loopback packet, otherwise FALSE
 */
bool_t
NET_UTILS_is_loopback_packet(const struct sk_buff *skb);

/**
 * @brief Check if an inet packet should be ignored (aka non TCP, UDP nor ICMP)
 * 
 * @param[in] skb
 *
 * @return TRUE if TCP/UDP/ICMP packet, otherwise FALSE
 */
bool_t
NET_UTILS_is_tcp_udp_icmp_packet(const struct sk_buff *skb);


/**
 * @brief Check if a given packet is a TCP packet with FIN+URG+PSH flags
 * 
 * @param[in] skb The packet to check
 *
 * @return TRUE if xmas packet, otherwise FALSE
 *
 * @remark If skb is NULL, the function will return FALSE
 */
bool_t
NET_UTILS_is_xmas_packet(const struct sk_buff *skb);


#endif /* __NET_UTILS_H__ */

