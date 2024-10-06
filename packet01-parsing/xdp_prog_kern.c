/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor
{
	void *pos;
};

struct vlan_hdr
{
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
			  h_proto == bpf_htons(ETH_P_8021AD));
}
/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
										void *data_end,
										struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */

	if (nh->pos + hdrsize > data_end)
	{
		return -1;
	}

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

#pragma unroll
	for (int i = 0; i < 10; i++)
	{
		if (!proto_is_vlan(h_proto))
			break;

		hdrsize = sizeof(*vlh);
		if (nh->pos + hdrsize > data_end)
		{
			return -1;
		}

		nh->pos += hdrsize;
		h_proto = vlh->h_vlan_encapsulated_proto;
	}
	return h_proto;
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
										void *data_end,
										struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize = sizeof(*iph);

	if (nh->pos + hdrsize > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if (nh->pos + hdrsize > data_end)
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
										void *data_end,
										struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6 = nh->pos;
	int hdrsize = sizeof(*ip6);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */

	if (nh->pos + hdrsize > data_end)
	{
		return -1;
	}

	nh->pos += hdrsize;
	*ip6hdr = ip6;

	return ip6->nexthdr;
}

static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
										  void *data_end,
										  struct icmphdr **icmphdr)
{
	struct icmphdr *icmp4 = nh->pos;
	int hdrsize = sizeof(*icmp4);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmphdr = icmp4;

	return icmp4->type;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
										  void *data_end,
										  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	int hdrsize = sizeof(*icmp6);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmp6;

	return icmp6->icmp6_type;
}

SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IPV6))
	{

		/* Assignment additions go below here */
		struct ipv6hdr *ip6;
		nh_type = parse_ip6hdr(&nh, data_end, &ip6);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		struct icmp6hdr *icmp6;
		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if ((bpf_ntohs(icmp6->icmp6_sequence) % 2) == 0)
		{
			action = XDP_DROP;
		}
	}
	else if (nh_type == bpf_htons(ETH_P_IP))
	{
		struct iphdr *ip4;
		nh_type = parse_ip4hdr(&nh, data_end, &ip4);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		struct icmphdr *icmp4;
		nh_type = parse_icmp4hdr(&nh, data_end, &icmp4);
		if (nh_type != ICMP_ECHO)
			goto out;

		if ((bpf_ntohs(icmp4->un.echo.sequence) % 2) == 0)
		{
			action = XDP_DROP;
		}
	}

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
