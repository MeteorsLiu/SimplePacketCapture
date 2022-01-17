#include <linux/if_packet.h>  // AF_PACKET, sockaddr_ll
#include <linux/if_ether.h>  // ETH_P_ALL
#include <sys/socket.h>  // socket()
#include <unistd.h>  // close()
#include <arpa/inet.h>  // htons()
#include <sys/mman.h>  // mmap(), munmap()
#include <poll.h>  // poll()
#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
//Global vars
static int snaplen = 65535;
static struct pcap_t *p = NULL;
static struct sock_filter *sof = NULL;


int pcapCompileBPF(const char *dev, const char *expr) {
   char errBuf[PCAP_ERRBUF_SIZE];
   bpf_u_int32 netp;
   bpf_u_int32 maskp;


   if pcap_lookupnet(dev, &netp, &maskp, errBuf) != 0 {
       printf("%s", errBuf);
       return -1;
   }

    if (!p) {
        p = pcap_open_dead(LINKTYPE_ETHERNET, snaplen);
    }
    struct bpf_program *fp = NULL;
    if pcap_compile(p, fp, expr, 1, maskp) != 0 {
        return -1;
    }
    assert(fp != NULL);
    
    sof->code = (__u16)fp->insns->code;
    sof->jt = (__u8)fp->insns->jt;
    sof->jf = (__u8)fp->insns->jf;
    sof->k = (__u32)fp->insns->k;

    pcap_freecode(fp);
}


void TPacketSetBPF(int fd) {
    if (!sof) {
        return;
    }
    setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, sof, sizeof(struct sock_filter))

}

int main (void) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    
    return 0;
}