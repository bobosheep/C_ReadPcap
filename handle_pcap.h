#ifndef HANDLE_PCAP_H
#define HANDLE_PCAP_H
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>


//ethernet header
typedef struct ETH_hdr eth_hdr;
/*
typedef struct eth_hdr { 
	u_char dst_mac[6]; 
	u_char src_mac[6]; 
	u_short eth_type; 
}eth_hdr; 
*/

//ipv4 header 
typedef struct IP_hdr ip_hdr;
/*
typedef struct ip_hdr { 
	int version:4; 
	int header_len:4; 
	u_char tos:8; 
	int total_len:16; 
	int ident:16; 
	int flags:16; 
	u_char ttl:8; 
	u_char protocol:8; 
	int checksum:16; 
	u_char sourceIP[4]; 
	u_char destIP[4]; 
}ip_hdr; 
*/

//ipv6 header
typedef struct IP6_hdr ip6_hdr;
/*
typedef struct ip6_hdr{
	unsigned int version:4;
	unsigned int traffic_class:8;
	unsigned int flow_label:20;
	uint16_t payload_len;
	uint8_t next_header;
	uint8_t hop_limit;
	union{
		struct ip6_hdrctl{
			uint32_t ip6_un1_flow;
			uint16_t ip6_un1_plen;
			uint8_t ip6_un1_nxt;
			uint8_t ip6_un1_hlim;
		}
		uint8_t ip6_un2_vfc;
	}ip6_ctlun
	uint16_t sourceIP[8];
	uint16_t destIP[8];
}ip6_hdr;
*/

//tcp header
typedef struct TCP_hdr tcp_hdr;
/*
typedef struct tcp_hdr { 
	u_short sport; 
	u_short dport; 
	u_int seq; 
	u_int ack; 
	u_char head_len; 
	u_char flags; 
	u_short wind_size; 
	u_short check_sum; 
	u_short urg_ptr; 
}tcp_hdr; 
*/

//udp header 
typedef struct UDP_hdr udp_hdr;
/*
typedef struct udp_hdr { 
	u_short sport; 
	u_short dport; 
	u_short tot_len; 
	u_short check_sum; 
}udp_hdr; 
*/

void p_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);


#endif