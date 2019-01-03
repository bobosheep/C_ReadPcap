#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "handle_pcap.h"

struct ETH_hdr 
{ 
	u_char dst_mac[6]; 
	u_char src_mac[6]; 
	u_short eth_type; 
};
struct IP_hdr 
{ 
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
};
struct IP6_hdr
{
	unsigned int version:4;
	unsigned int traffic_class:8;
	unsigned int flow_label:20;
	uint16_t payload_len;
	uint8_t next_header;
	uint8_t hop_limit;
    /*
	union{
		struct ip6_hdrctl{
			uint32_t ip6_un1_flow;
			uint16_t ip6_un1_plen;
			uint8_t ip6_un1_nxt;
			uint8_t ip6_un1_hlim;
		}
		uint8_t ip6_un2_vfc;
	}ip6_ctlun*/
	uint16_t sourceIP[8];
	uint16_t destIP[8];
};
struct TCP_hdr 
{ 
	u_short sport; 
	u_short dport; 
	u_int seq; 
	u_int ack; 
	u_char head_len; 
	u_char flags; 
	u_short wind_size; 
	u_short check_sum; 
	u_short urg_ptr; 
};
struct UDP_hdr
{ 
	u_short sport; 
	u_short dport; 
	u_short tot_len; 
	u_short check_sum; 
};

eth_hdr *ethernet;
ip_hdr *ip;
ip6_hdr *ip6;
tcp_hdr *tcp;
udp_hdr *udp;


//this function will be called when we get packet
void p_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	static int count=0;
    int len;
    char* printtime;
	count++;
	
	
    printtime = ctime((const time_t*)&pkt_header->ts.tv_sec);
    len = strlen(printtime);
    printtime[len - 1] = '\0';


    printf("-----------------------packet #%d-------------------------\n",count);		//packet number
	printf("| packet length\t|\t\t%d\t\t\t|\n", pkt_header->len);			//length of packet
	
    printf("| capture time\t|\t%s\t|\n", printtime);//get packet time
	//length of header
	u_int eth_len=sizeof(eth_hdr); 
	u_int ip_len=sizeof(ip_hdr);
	u_int ip6_len=sizeof(ip6_hdr); 
	u_int tcp_len=sizeof(tcp_hdr); 
	u_int udp_len=sizeof(udp_hdr); 
	
	ethernet=(eth_hdr *)pkt_data; 
	//decided which type of protocl of ethernet ipv4 or ipv6 or others
	if(ntohs(ethernet->eth_type)==0x0800)
    { //ipv4
		//printf("IPV4 is used\n"); 
		//printf("IPV4 header information:\n"); 
		ip=(ip_hdr*)(pkt_data+eth_len); 
		printf("| source ip\t|\t\t%d.%d.%d.%d\t\t\t|\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]); 
		printf("| dest ip\t|\t\t%d.%d.%d.%d\t\t\t|\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]); 
		if(ip->protocol==6)
        { 	//tcp
			//printf("tcp is used:\n"); 
			tcp=(tcp_hdr*)(pkt_data+eth_len+ip_len); 
            printf("| tcp source port\t|\t\t%u\t\t\t|\n",htons(tcp->sport));
            printf("| tcp dest port\t|\t\t%u\t\t\t|\n",htons(tcp->dport));
		}
		else if(ip->protocol==17)
        { //udp protocl
			//printf("udp is used:\n"); 
			udp=(udp_hdr*)(pkt_data+eth_len+ip_len); 
            printf("| udp source port\t|\t\t%u\t\t|\n",htons(udp->sport));
            printf("| udp dest port\t|\t\t%u\t\t|\n",htons(udp->dport));
		 } 
		else
        { 
			printf("|\tother transport protocol is used\t\t|\n"); 
		} 
	} 
	else if(ntohs(ethernet->eth_type)==0x086dd) 
    { //ipv6
		//printf("ipv6 is used\n"); 
		ip6=(ip6_hdr*)(pkt_data+eth_len);
		char str[INET6_ADDRSTRLEN];
		printf("| source ip6\t|\t\t%s\t\t|\n",inet_ntop(AF_INET6,ip6->sourceIP,str,sizeof(str)));
		printf("| dest ip6\t|\t\t%s\t\t|\n",inet_ntop(AF_INET6,ip6->destIP,str,sizeof(str)));
        if(ip6->next_header==6)
        {	//tcp
            //printf("tcp is used:\n");
            tcp=(tcp_hdr*)(pkt_data+eth_len+ip6_len);
            printf("| tcp source port\t|\t\t%u\t\t\t|\n",htons(tcp->sport));
            printf("| tcp dest port\t|\t\t%u\t\t\t|\n",htons(tcp->dport));
        }
        else if(ip6->next_header==17)
        {	//udp
            //printf("udp is used:\n");
            udp=(udp_hdr*)(pkt_data+eth_len+ip6_len);
            printf("| udp source port\t|\t\t%u\t\t|\n",htons(udp->sport));
            printf("| udp dest port\t|\t\t%u\t\t|\n",htons(udp->dport));
        }
        else 
        {
            printf("|\t\tother transport protocol is used\t\t|\n"); 
        }
	} 
	else
    {
		printf("|\t\tother ethernet_type\t\t\t|\n");
	}
	printf("---------------------------------------------------------\n"); 
	printf("\n");
}