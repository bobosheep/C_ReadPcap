all: main.c handle_pcap.c
	gcc main.c handle_pcap.c -lpcap -o readpcap