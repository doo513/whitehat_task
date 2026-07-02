#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void print_mac(const char *name, u_char *mac)
{
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           name,
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

void print_message(const u_char *msg, int msg_len)
{
    printf("         Message Length: %d\n", msg_len);

    if (msg_len <= 0) {
        printf("         Message: 없음\n");
        return;
    }

    printf("         HTTPMessage:\n");

    for (int i = 0; i < msg_len; i++) {
        if (msg[i] >= 32 && msg[i] <= 126) {
            putchar(msg[i]);
        } else if (msg[i] == '\r' || msg[i] == '\n' || msg[i] == '\t') {
            putchar(msg[i]);
        } else {
            putchar('.');
        }
    }

    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) /*packet은 캡처된 패킷 데이터 시작 주소*/
{
  struct ethheader *eth = (struct ethheader *)packet;
  
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    struct tcpheader * port = (struct tcpheader *)
                           (packet + sizeof(struct ethheader) + ip->iph_ihl * 4);
    unsigned int msg_len = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - (port->tcp_offx2 >> 4) * 4;
    const u_char *msg = (const u_char *)
                           (packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + (port->tcp_offx2 >> 4) * 4);

    print_mac("      Src Mac : ", eth->ether_shost);
    print_mac("      Dst Mac : ", eth->ether_dhost);

    printf("         Src Ip : %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         Dst IP : %s\n", inet_ntoa(ip->iph_destip));    

    printf("         Src Port: %d\n", ntohs(port->tcp_sport));
    printf("         Dst Port: %d\n", ntohs(port->tcp_dport));

    print_message(msg, msg_len);

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the hand
  return 0;
}
