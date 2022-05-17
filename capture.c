#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h> 

//Global
static pcap_t *p = NULL;
#define ERROR -1

void stop_capture(int o) {
	printf("Exit");
	pcap_close(p);
	p = NULL;
}

int create_pcap_handle(char* device, char* filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    // If no network interface (device) is specfied, get the first one.
    if (device == NULL) {
    	return ERROR;
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        return ERROR;
    }

    // Open the device for live capture.
    p = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
    if (p == NULL) {
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
        return ERROR;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(p, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        fprintf(stderr, "pcap_compile(): %s\n", pcap_geterr(p));
        return ERROR;
    }

    // Bind the packet filter to the libpcap p.
    if (pcap_setfilter(p, &bpf) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(p));
        return ERROR;
    }

    //All done :)
    return 0;
}


void packetHandler(
    u_char *args,
    const struct pcap_pkthdr* header,
    const u_char* packet
) {
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    //Only IP Packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    	//Get IP Header
    	struct iphdr * ip_header = (struct iphdr *) (packet + sizeof(struct ether_header));
    	//We only need the src ip
    	//no need to parse the tcp header in advance
    	printf("%s\n", inet_ntoa(ip_header->saddr));
    }
}


// Argv
int main(int argc, char const *argv[])
{

    if (create_pcap_handle(argv[1], argv[2]) == ERROR)
    	exit(0);

    //Register Signal
    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    signal(SIGQUIT, stop_capture);

    // Start Loop
    pcap_loop(p, 0, packetHandler, NULL);

	return 0;
}