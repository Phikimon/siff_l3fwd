/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/md5.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include "l3fwd.h"
#include "l3fwd_event.h"

#include "l3fwd_route.h"

#define IPV4_L3FWD_LPM_MAX_RULES         1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)
#define IPV6_L3FWD_LPM_MAX_RULES         1024
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

static struct rte_lpm *ipv4_l3fwd_lpm_lookup_struct[NB_SOCKETS];
static struct rte_lpm6 *ipv6_l3fwd_lpm_lookup_struct[NB_SOCKETS];

#define IPV4_OPT_SIFF 0x4A
#define IPV4_OPT_SIFF_CAP_SIZE 4
#define IPV4_OPT_SIFF_DTA_MASK 0x80
#define IPV4_OPT_SIFF_CU_MASK 0x40
#define IPV4_OPT_SIFF_MARKING_MASK 0x0F

/* Performing LPM-based lookups. 8< */
static inline uint16_t
lpm_get_ipv4_dst_port(const struct rte_ipv4_hdr *ipv4_hdr,
		      uint16_t portid,
		      struct rte_lpm *ipv4_l3fwd_lookup_struct)
{
	uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	uint32_t next_hop;

	if (rte_lpm_lookup(ipv4_l3fwd_lookup_struct, dst_ip, &next_hop) == 0)
		return next_hop;
	else
		return portid;
}
/* >8 End of performing LPM-based lookups. */

static inline uint16_t
lpm_get_ipv6_dst_port(const struct rte_ipv6_hdr *ipv6_hdr,
		      uint16_t portid,
		      struct rte_lpm6 *ipv6_l3fwd_lookup_struct)
{
	const uint8_t *dst_ip = ipv6_hdr->dst_addr;
	uint32_t next_hop;

	if (rte_lpm6_lookup(ipv6_l3fwd_lookup_struct, dst_ip, &next_hop) == 0)
		return next_hop;
	else
		return portid;
}

static __rte_always_inline uint16_t
lpm_get_dst_port(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
		uint16_t portid)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

		return lpm_get_ipv4_dst_port(ipv4_hdr, portid,
					     qconf->ipv4_lookup_struct);
	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		return lpm_get_ipv6_dst_port(ipv6_hdr, portid,
					     qconf->ipv6_lookup_struct);
	}

	return portid;
}

/*
 * lpm_get_dst_port optimized routine for packets where dst_ipv4 is already
 * precalculated. If packet is ipv6 dst_addr is taken directly from packet
 * header and dst_ipv4 value is not used.
 */
static __rte_always_inline uint16_t
lpm_get_dst_port_with_ipv4(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
	uint32_t dst_ipv4, uint16_t portid)
{
	uint32_t next_hop;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		return (uint16_t) ((rte_lpm_lookup(qconf->ipv4_lookup_struct,
						   dst_ipv4, &next_hop) == 0)
				   ? next_hop : portid);

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		return (uint16_t) ((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				ipv6_hdr->dst_addr, &next_hop) == 0)
				? next_hop : portid);

	}

	return portid;
}

#undef RTE_ARCH_X86

static uint8_t*
find_ipv4_option(uint8_t *ipv4_hdr, uint8_t option_number)
{
#define IPV4_IHL_MASK 0x0F
#define IPV4_OPT_EOOL 0
#define IPV4_OPT_NOP 1
	if (ipv4_hdr == NULL)
		return NULL;

	uint8_t ihl = ipv4_hdr[0] & IPV4_IHL_MASK;
	if (ihl < 5)
		return NULL;

	uint8_t options_len = (ihl - 5) * 4;
	if (options_len == 0)
		return NULL;

	uint8_t *opt_ptr = ipv4_hdr + 20;

	while (options_len > 0) {
		uint8_t opt = *opt_ptr;
		if (opt == IPV4_OPT_EOOL) {
			break;
		} else if (opt == IPV4_OPT_NOP) {
			opt_ptr++;
			options_len--;
		} else {
			uint8_t opt_len = *(opt_ptr + 1);
			if (options_len < opt_len || opt_len < 2)
				break;

			if (opt == option_number)
				return opt_ptr;

			opt_ptr += opt_len;
			options_len -= opt_len;
		}
	}

	return NULL;
#undef IPV4_IHL_MASK
#undef IPV4_OPT_EOOL
#undef IPV4_OPT_NOP
}

int
process_dta_cap(uint8_t* cap_ptr, uint8_t new_marking, uint8_t old_marking) {
	// A mask to extract the 2 most significant bits (PT and CU flags)
	uint32_t msb_mask = 0xC0000000;

	uint32_t capability = ((uint32_t)cap_ptr[0] << 24) |
		((uint32_t)cap_ptr[1] << 16) |
		((uint32_t)cap_ptr[2] << 8) |
		(uint32_t)cap_ptr[3];

	// Save the PT and CU flags
	uint32_t msb = capability & msb_mask;

	// Clear the flags from the capability
	capability &= ~msb_mask;
	fprintf(stderr, "%d: marking in packet %01X\n", __LINE__, capability & IPV4_OPT_SIFF_MARKING_MASK);

	// Check if this router's marking is correct
	if ((capability & IPV4_OPT_SIFF_MARKING_MASK) != new_marking &&
		(capability & IPV4_OPT_SIFF_MARKING_MASK) != old_marking) {
		// Drop the packet
		return 1;
	}

	// Shift the new marking to the 4 most significant bits of the capability
	// (skipping the space occupied by flags)
	capability = (capability >> 4) | (new_marking << 24);

	// Restore the flags
	capability |= msb;

	cap_ptr[0] = (uint8_t)(capability >> 24);
	cap_ptr[1] = (uint8_t)(capability >> 16);
	cap_ptr[2] = (uint8_t)(capability >> 8);
	cap_ptr[3] = (uint8_t)(capability);

	return 0;
}

void
process_exp_cap(uint8_t* cap_ptr, uint8_t marking) {
	// A mask to extract the 2 most significant bits (PT and CU flags)
	uint32_t msb_mask = 0xC0000000;

	uint32_t capability = ((uint32_t)cap_ptr[0] << 24) |
		((uint32_t)cap_ptr[1] << 16) |
		((uint32_t)cap_ptr[2] << 8) |
		(uint32_t)cap_ptr[3];

	// Save the PT and CU flags
	uint32_t msb = capability & msb_mask;

	// Clear the flags from the capability
	capability &= ~msb_mask;

	// If the capability is zero, append 1 bit to the left of the marking
	// (as per the paper)
	if (capability == 0) {
		marking |= 0x10;
	}

	capability = (capability << 4) | marking;

	// Restore the flags
	capability |= msb;

	cap_ptr[0] = (uint8_t)(capability >> 24);
	cap_ptr[1] = (uint8_t)(capability >> 16);
	cap_ptr[2] = (uint8_t)(capability >> 8);
	cap_ptr[3] = (uint8_t)(capability);
}

/* Arguments should be pointers to 4-byte arrays (i.e. IP addresses) */
unsigned int
marking_hash(size_t count, uint8_t key, ...)
{
	MD5_CTX c;
	unsigned char digest[16];
	va_list args;
	int i, j;

	va_start(args, key);
	MD5_Init(&c);

	MD5_Update(&c, &key, 1);

	for (i = 0; i < count; i++) {
		const uint8_t* bytes = va_arg(args, const uint8_t*);

		MD5_Update(&c, bytes, 4);
	}

	MD5_Final(digest, &c);
	va_end(args);

	return digest[15] & 0xF;
}

static uint16_t ones_complement_sum(uint16_t a, uint16_t b)
{
	uint32_t sum = (uint32_t)a + (uint32_t)b;
	sum = (sum & 0xFFFF) + (sum >> 16);
	sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)(sum & 0xFFFF);
}

static uint16_t ipv4_options_cksum(const struct rte_ipv4_hdr* ipv4_hdr)
{
	uint16_t* data = (uint16_t*)(ipv4_hdr+1);
	uint16_t cksum = 0;
	int i;
	for (i = 0; i < (ipv4_hdr->ihl-5)*2; i++) {
		cksum = ones_complement_sum(cksum, rte_be_to_cpu_16(*data));
		data++;
	}
	return cksum;
}

static void
handle_siff(struct rte_ipv4_hdr* ipv4_hdr, int* is_dropping, int* is_priority)
{
	uint8_t *option_ptr = find_ipv4_option((uint8_t*)ipv4_hdr, IPV4_OPT_SIFF);
	if (option_ptr == NULL) {
		*is_dropping = 0;
		*is_priority = 0;
		return;
	}

	int is_dta = !!(option_ptr[2] & IPV4_OPT_SIFF_DTA_MASK);
	int is_exp = !is_dta;
	int is_cu = !!(option_ptr[2] & IPV4_OPT_SIFF_CU_MASK);
	fprintf(stderr, "is_dta = %d, is_exp = %d, is_cu = %d\n",
			is_dta, is_exp, is_cu);

	// Verify option length
	int optlen = option_ptr[1];
	if (optlen != 2 + (1+is_cu) * IPV4_OPT_SIFF_CAP_SIZE) {
		*is_dropping = 0;
		*is_priority = 0;
		return;
	}

	static time_t timecode = 0;
	time_t new_timecode = time(NULL) / 15;
	static uint8_t key = 0;
	if (new_timecode != timecode) {
		timecode = new_timecode;
		key++;
		fprintf(stderr, "_________________________CHANGING KEY = %d_________________________\n", key);
	}
	// Endianness doesn't matter for hashing
	const uint8_t* src_addr = (const uint8_t*)&ipv4_hdr->src_addr;
	const uint8_t* dst_addr = (const uint8_t*)&ipv4_hdr->dst_addr;
	/* last hop routers IP address and this interface's IP address
	 * can also be added in the mix, this is why marking_hash()
	 * accepts arbitraty number of arguments */
	uint8_t new_marking = (uint8_t)marking_hash(2, key,     src_addr, dst_addr);
	new_marking += (new_marking == 0); // The paper has a 'bug' - zero markings do not work
	fprintf(stderr, "%d: new_marking %01X\n", __LINE__, new_marking);

	uint8_t old_marking = (uint8_t)marking_hash(2, key - 1, src_addr, dst_addr);
	old_marking += (old_marking == 0); // The paper has a 'bug' - zero markings do not work
	fprintf(stderr, "%d: old_marking %01X\n", __LINE__, old_marking);

	uint8_t expired_marking = (uint8_t)marking_hash(2, key - 2, src_addr, dst_addr);
	expired_marking += (expired_marking == 0);
	fprintf(stderr, "%d: expired_marking %01X\n", __LINE__, expired_marking);

	if (is_exp) {
		process_exp_cap(&option_ptr[2], new_marking);
		*is_dropping = 0;
		*is_priority = 0;
	} else if (is_dta) {
		if (process_dta_cap(&option_ptr[2], new_marking, old_marking)) {
			*is_dropping = 1;
			*is_priority = 0;
		} else {
			*is_dropping = 0;
			*is_priority = 1;
		}
	}

}

static inline void
l3fwd_lpm_simple_forward(struct rte_mbuf *m, uint16_t portid,
		struct lcore_conf *qconf)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint16_t dst_port;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {
		/* Handle IPv4 headers.*/
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
						sizeof(struct rte_ether_hdr));

#ifdef DO_RFC_1812_CHECKS
		/* Check to make sure the packet is valid (RFC1812) */
		if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt_len) < 0) {
			rte_pktmbuf_free(m);
			return;
		}
#endif

		int siff_compliant = 0;
		if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
			struct rte_udp_hdr *udp;
			udp = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
					sizeof(struct rte_ether_hdr)+(ipv4_hdr->ihl*4));
			if (rte_be_to_cpu_16(udp->dst_port) == 54321 || rte_be_to_cpu_16(udp->src_port) == 54321) {
				siff_compliant = 1;
				RTE_LOG(INFO, L3FWD, "\n\nPort %d: received a UDP %d/%d packet!\n", portid,
						rte_be_to_cpu_16(udp->dst_port), rte_be_to_cpu_16(udp->src_port));
				int is_dropping = 0, is_priority = 0;

				uint16_t old_cksum = ipv4_options_cksum(ipv4_hdr);

				handle_siff(ipv4_hdr, &is_dropping, &is_priority);

				int16_t cksum_difference = ones_complement_sum(ipv4_options_cksum(ipv4_hdr), ~old_cksum);

				// see https://www.rfc-editor.org/rfc/rfc1071
				ipv4_hdr->hdr_checksum = ones_complement_sum(ipv4_hdr->hdr_checksum, ~rte_be_to_cpu_16(cksum_difference));

				fprintf(stderr, "is_drop = %d, is_prio = %d\n", is_dropping, is_priority);
				if (is_dropping) {
					fprintf(stderr, "Dropping a packet with wrong marking\n");
					rte_pktmbuf_free(m);
					return;
				}
				if (!is_priority) {
					fprintf(stderr, "Low priority packet\n");
					///if ((time(NULL) / 3) % 2) {
					///	fprintf(stderr, "Dropping low priority packet\n");
					///	rte_pktmbuf_free(m);
					///	return;
					///}
				}
				if (!is_dropping && is_priority)
					fprintf(stderr, "High priority packet\n");
			}
		}

		dst_port = lpm_get_ipv4_dst_port(ipv4_hdr, portid,
						qconf->ipv4_lookup_struct);

		if (dst_port >= RTE_MAX_ETHPORTS ||
			(enabled_port_mask & 1 << dst_port) == 0)
			dst_port = portid;

#ifdef DO_RFC_1812_CHECKS
		/* Update time to live and header checksum */
		--(ipv4_hdr->time_to_live);
		++(ipv4_hdr->hdr_checksum);
#endif
		/* dst addr */
		*(uint64_t *)&eth_hdr->dst_addr = dest_eth_addr[dst_port];

		/* src addr */
		rte_ether_addr_copy(&ports_eth_addr[dst_port],
				&eth_hdr->src_addr);

		send_single_packet(qconf, m, dst_port);
	} else if (RTE_ETH_IS_IPV6_HDR(m->packet_type)) {
		/* Handle IPv6 headers.*/
		struct rte_ipv6_hdr *ipv6_hdr;

		ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
						sizeof(struct rte_ether_hdr));

		dst_port = lpm_get_ipv6_dst_port(ipv6_hdr, portid,
					qconf->ipv6_lookup_struct);

		if (dst_port >= RTE_MAX_ETHPORTS ||
			(enabled_port_mask & 1 << dst_port) == 0)
			dst_port = portid;

		/* dst addr */
		*(uint64_t *)&eth_hdr->dst_addr = dest_eth_addr[dst_port];

		/* src addr */
		rte_ether_addr_copy(&ports_eth_addr[dst_port],
				&eth_hdr->src_addr);

		send_single_packet(qconf, m, dst_port);
	} else {
		/* Free the mbuf that contains non-IPV4/IPV6 packet */
		rte_pktmbuf_free(m);
	}
	/* We can process ARP requests here */
}

static inline void
l3fwd_lpm_no_opt_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
				uint16_t portid, struct lcore_conf *qconf)
{
	int32_t j;

	/* Prefetch first packets */
	for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));

	/* Prefetch and forward already prefetched packets. */
	for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
				j + PREFETCH_OFFSET], void *));
		l3fwd_lpm_simple_forward(pkts_burst[j], portid, qconf);
	}

	/* Forward remaining prefetched packets */
	for (; j < nb_rx; j++)
		l3fwd_lpm_simple_forward(pkts_burst[j], portid, qconf);
}


/* main processing loop */
int
lpm_main_loop(__rte_unused void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, nb_rx;
	uint16_t portid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	const uint16_t n_rx_q = qconf->n_rx_queue;
	const uint16_t n_tx_p = qconf->n_tx_port;
	if (n_rx_q == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < n_rx_q; i++) {

		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	cur_tsc = rte_rdtsc();
	prev_tsc = cur_tsc;

	while (!force_quit) {

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < n_tx_p; ++i) {
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf,
					qconf->tx_mbufs[portid].len,
					portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < n_rx_q; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				MAX_PKT_BURST);
			if (nb_rx == 0)
				continue;

#if defined RTE_ARCH_X86 || defined __ARM_NEON \
			 || defined RTE_ARCH_PPC_64
			l3fwd_lpm_send_packets(nb_rx, pkts_burst,
						portid, qconf);
#else
			l3fwd_lpm_no_opt_send_packets(nb_rx, pkts_burst,
							portid, qconf);
#endif /* X86 */
		}

		cur_tsc = rte_rdtsc();
	}

	return 0;
}

static __rte_always_inline uint16_t
lpm_process_event_pkt(const struct lcore_conf *lconf, struct rte_mbuf *mbuf)
{
	mbuf->port = lpm_get_dst_port(lconf, mbuf, mbuf->port);

#if defined RTE_ARCH_X86 || defined __ARM_NEON \
	|| defined RTE_ARCH_PPC_64
	process_packet(mbuf, &mbuf->port);
#else

	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf,
			struct rte_ether_hdr *);
#ifdef DO_RFC_1812_CHECKS
	struct rte_ipv4_hdr *ipv4_hdr;
	if (RTE_ETH_IS_IPV4_HDR(mbuf->packet_type)) {
		/* Handle IPv4 headers.*/
		ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,
				struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));

		if (is_valid_ipv4_pkt(ipv4_hdr, mbuf->pkt_len)
				< 0) {
			mbuf->port = BAD_PORT;
			return mbuf->port;
		}
		/* Update time to live and header checksum */
		--(ipv4_hdr->time_to_live);
		++(ipv4_hdr->hdr_checksum);
	}
#endif
	/* dst addr */
	*(uint64_t *)&eth_hdr->dst_addr = dest_eth_addr[mbuf->port];

	/* src addr */
	rte_ether_addr_copy(&ports_eth_addr[mbuf->port],
			&eth_hdr->src_addr);
#endif
	return mbuf->port;
}

static __rte_always_inline void
lpm_event_loop_single(struct l3fwd_event_resources *evt_rsrc,
		const uint8_t flags)
{
	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[
		evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	struct lcore_conf *lconf;
	unsigned int lcore_id;
	struct rte_event ev;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();
	lconf = &lcore_conf[lcore_id];

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);
	while (!force_quit) {
		if (!rte_event_dequeue_burst(event_d_id, event_p_id, &ev, 1, 0))
			continue;

		if (lpm_process_event_pkt(lconf, ev.mbuf) == BAD_PORT) {
			rte_pktmbuf_free(ev.mbuf);
			continue;
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			ev.queue_id = tx_q_id;
			ev.op = RTE_EVENT_OP_FORWARD;
			while (rte_event_enqueue_burst(event_d_id, event_p_id,
						&ev, 1) && !force_quit)
				;
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			rte_event_eth_tx_adapter_txq_set(ev.mbuf, 0);
			while (!rte_event_eth_tx_adapter_enqueue(event_d_id,
						event_p_id, &ev, 1, 0) &&
					!force_quit)
				;
		}
	}
}

static __rte_always_inline void
lpm_event_loop_burst(struct l3fwd_event_resources *evt_rsrc,
		const uint8_t flags)
{
	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[
		evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	const uint16_t deq_len = evt_rsrc->deq_depth;
	struct rte_event events[MAX_PKT_BURST];
	struct lcore_conf *lconf;
	unsigned int lcore_id;
	int i, nb_enq, nb_deq;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();

	lconf = &lcore_conf[lcore_id];

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);

	while (!force_quit) {
		/* Read events from RX queues */
		nb_deq = rte_event_dequeue_burst(event_d_id, event_p_id,
				events, deq_len, 0);
		if (nb_deq == 0) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_deq; i++) {
			if (flags & L3FWD_EVENT_TX_ENQ) {
				events[i].queue_id = tx_q_id;
				events[i].op = RTE_EVENT_OP_FORWARD;
			}

			if (flags & L3FWD_EVENT_TX_DIRECT)
				rte_event_eth_tx_adapter_txq_set(events[i].mbuf,
								 0);

			lpm_process_event_pkt(lconf, events[i].mbuf);
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			nb_enq = rte_event_enqueue_burst(event_d_id, event_p_id,
					events, nb_deq);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_enqueue_burst(event_d_id,
						event_p_id, events + nb_enq,
						nb_deq - nb_enq);
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			nb_enq = rte_event_eth_tx_adapter_enqueue(event_d_id,
					event_p_id, events, nb_deq, 0);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_eth_tx_adapter_enqueue(
						event_d_id, event_p_id,
						events + nb_enq,
						nb_deq - nb_enq, 0);
		}
	}
}

static __rte_always_inline void
lpm_event_loop(struct l3fwd_event_resources *evt_rsrc,
		 const uint8_t flags)
{
	if (flags & L3FWD_EVENT_SINGLE)
		lpm_event_loop_single(evt_rsrc, flags);
	if (flags & L3FWD_EVENT_BURST)
		lpm_event_loop_burst(evt_rsrc, flags);
}

int __rte_noinline
lpm_event_main_loop_tx_d(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_DIRECT | L3FWD_EVENT_SINGLE);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_d_burst(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_DIRECT | L3FWD_EVENT_BURST);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_ENQ | L3FWD_EVENT_SINGLE);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q_burst(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_ENQ | L3FWD_EVENT_BURST);
	return 0;
}

static __rte_always_inline void
lpm_process_event_vector(struct rte_event_vector *vec, struct lcore_conf *lconf)
{
	struct rte_mbuf **mbufs = vec->mbufs;
	int i;

	/* Process first packet to init vector attributes */
	lpm_process_event_pkt(lconf, mbufs[0]);
	if (vec->attr_valid) {
		if (mbufs[0]->port != BAD_PORT)
			vec->port = mbufs[0]->port;
		else
			vec->attr_valid = 0;
	}

	for (i = 1; i < vec->nb_elem; i++) {
		lpm_process_event_pkt(lconf, mbufs[i]);
		event_vector_attr_validate(vec, mbufs[i]);
	}
}

/* Same eventdev loop for single and burst of vector */
static __rte_always_inline void
lpm_event_loop_vector(struct l3fwd_event_resources *evt_rsrc,
		      const uint8_t flags)
{
	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id =
		evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	const uint16_t deq_len = evt_rsrc->deq_depth;
	struct rte_event events[MAX_PKT_BURST];
	struct lcore_conf *lconf;
	unsigned int lcore_id;
	int i, nb_enq, nb_deq;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();
	lconf = &lcore_conf[lcore_id];

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);

	while (!force_quit) {
		/* Read events from RX queues */
		nb_deq = rte_event_dequeue_burst(event_d_id, event_p_id, events,
						 deq_len, 0);
		if (nb_deq == 0) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_deq; i++) {
			if (flags & L3FWD_EVENT_TX_ENQ) {
				events[i].queue_id = tx_q_id;
				events[i].op = RTE_EVENT_OP_FORWARD;
			}

			lpm_process_event_vector(events[i].vec, lconf);

			if (flags & L3FWD_EVENT_TX_DIRECT)
				event_vector_txq_set(events[i].vec, 0);
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			nb_enq = rte_event_enqueue_burst(event_d_id, event_p_id,
							 events, nb_deq);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_enqueue_burst(
					event_d_id, event_p_id, events + nb_enq,
					nb_deq - nb_enq);
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			nb_enq = rte_event_eth_tx_adapter_enqueue(
				event_d_id, event_p_id, events, nb_deq, 0);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_eth_tx_adapter_enqueue(
					event_d_id, event_p_id, events + nb_enq,
					nb_deq - nb_enq, 0);
		}
	}
}

int __rte_noinline
lpm_event_main_loop_tx_d_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	lpm_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_DIRECT);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_d_burst_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	lpm_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_DIRECT);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	lpm_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_ENQ);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q_burst_vector(__rte_unused void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	lpm_event_loop_vector(evt_rsrc, L3FWD_EVENT_TX_ENQ);
	return 0;
}

void
setup_lpm(const int socketid)
{
	struct rte_eth_dev_info dev_info;
	struct rte_lpm6_config config;
	struct rte_lpm_config config_ipv4;
	unsigned i;
	int ret;
	char s[64];
	char abuf[INET6_ADDRSTRLEN];

	/* create the LPM table */
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
	ipv4_l3fwd_lpm_lookup_struct[socketid] =
			rte_lpm_create(s, socketid, &config_ipv4);
	if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
	for (i = 0; i < RTE_DIM(ipv4_l3fwd_route_array); i++) {
		struct in_addr in;

		/* skip unused ports */
		if ((1 << ipv4_l3fwd_route_array[i].if_out &
				enabled_port_mask) == 0)
			continue;

		rte_eth_dev_info_get(ipv4_l3fwd_route_array[i].if_out,
				     &dev_info);
		ret = rte_lpm_add(ipv4_l3fwd_lpm_lookup_struct[socketid],
			ipv4_l3fwd_route_array[i].ip,
			ipv4_l3fwd_route_array[i].depth,
			ipv4_l3fwd_route_array[i].if_out);

		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		in.s_addr = htonl(ipv4_l3fwd_route_array[i].ip);
		printf("LPM: Adding route %s / %d (%d) [%s]\n",
		       inet_ntop(AF_INET, &in, abuf, sizeof(abuf)),
		       ipv4_l3fwd_route_array[i].depth,
		       ipv4_l3fwd_route_array[i].if_out, dev_info.device->name);
	}

	/* create the LPM6 table */
	snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

	config.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
	config.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
	config.flags = 0;
	ipv6_l3fwd_lpm_lookup_struct[socketid] = rte_lpm6_create(s, socketid,
				&config);
	if (ipv6_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
	for (i = 0; i < RTE_DIM(ipv6_l3fwd_route_array); i++) {

		/* skip unused ports */
		if ((1 << ipv6_l3fwd_route_array[i].if_out &
				enabled_port_mask) == 0)
			continue;

		rte_eth_dev_info_get(ipv4_l3fwd_route_array[i].if_out,
				     &dev_info);
		ret = rte_lpm6_add(ipv6_l3fwd_lpm_lookup_struct[socketid],
			ipv6_l3fwd_route_array[i].ip,
			ipv6_l3fwd_route_array[i].depth,
			ipv6_l3fwd_route_array[i].if_out);

		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		printf("LPM: Adding route %s / %d (%d) [%s]\n",
		       inet_ntop(AF_INET6, ipv6_l3fwd_route_array[i].ip, abuf,
				 sizeof(abuf)),
		       ipv6_l3fwd_route_array[i].depth,
		       ipv6_l3fwd_route_array[i].if_out, dev_info.device->name);
	}
}

int
lpm_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		if (ptypes[i] & RTE_PTYPE_L3_IPV4)
			ptype_l3_ipv4 = 1;
		if (ptypes[i] & RTE_PTYPE_L3_IPV6)
			ptype_l3_ipv6 = 1;
	}

	if (ptype_l3_ipv4 == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);

	if (ptype_l3_ipv6 == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);

	if (ptype_l3_ipv4 && ptype_l3_ipv6)
		return 1;

	return 0;

}

static inline void
lpm_parse_ptype(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
	else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

	m->packet_type = packet_type;
}

uint16_t
lpm_cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused,
		   struct rte_mbuf *pkts[], uint16_t nb_pkts,
		   uint16_t max_pkts __rte_unused,
		   void *user_param __rte_unused)
{
	unsigned int i;

	if (unlikely(nb_pkts == 0))
		return nb_pkts;
	rte_prefetch0(rte_pktmbuf_mtod(pkts[0], struct ether_hdr *));
	for (i = 0; i < (unsigned int) (nb_pkts - 1); ++i) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i+1],
			struct ether_hdr *));
		lpm_parse_ptype(pkts[i]);
	}
	lpm_parse_ptype(pkts[i]);

	return nb_pkts;
}

/* Return ipv4/ipv6 lpm fwd lookup struct. */
void *
lpm_get_ipv4_l3fwd_lookup_struct(const int socketid)
{
	return ipv4_l3fwd_lpm_lookup_struct[socketid];
}

void *
lpm_get_ipv6_l3fwd_lookup_struct(const int socketid)
{
	return ipv6_l3fwd_lpm_lookup_struct[socketid];
}
