#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "handle_pcap.h"


int main(int argc,char *argv[])
{
    pcap_t *handle;                  

    char errbuf[PCAP_ERRBUF_SIZE]; //¿¿¿¿

    bpf_u_int32 mask;               //¿¿
    bpf_u_int32 net;              

    struct bpf_program filter;      //bpf¿¿

    handle = pcap_open_offline(argv[1], errbuf);
    /*¿¿bpf¿¿¿¿ */
    pcap_compile(handle, &filter,argv[2], 0, net);
    pcap_setfilter(handle, &filter);

    /*¿¿¿¿¿¿*/
    pcap_loop(handle,-1,p_handler,NULL);
    pcap_close(handle);

    	return(0);
}