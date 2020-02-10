#include <cstdio>
#include <pcap.h>
#include "packet_headers.h"

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  int idx = 0; // packet index
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    EthernetHeaderPtr eth =
        reinterpret_cast<EthernetHeaderPtr>(const_cast<u_char*>(packet));
    IPHeaderPtr ip = reinterpret_cast<IPHeaderPtr>(
        reinterpret_cast<char*>(eth) + sizeof(EthernetHeader));

    printf("\nPacket %d:\n", idx++);
    puts("    Ethernet Header");
    puts("    =================");
    printf("    Source MAC: ");
    print_mac(eth->src);
    printf("\n    Destination MAC: ");
    print_mac(eth->dest);

    // If netwrok layer uses IP
    if (ntohs(eth->type) == ETHER_TYPE_IP) {
      uint16_t ip_header_len =
          static_cast<uint16_t>((ip->ip_version_header_length & 0xf) << 2);
      TCPHeaderPtr tcp = reinterpret_cast<TCPHeaderPtr>(
          reinterpret_cast<char*>(ip) + ip_header_len);

      puts("\n\n    IP Header");
      puts("    =================");
      printf("    Source IP: ");
      print_ip(ip->ip_srcaddr);
      printf("\n    Destination IP: ");
      print_ip(ip->ip_destaddr);

      // If transport layer uses TCP
      if (ip->ip_protocol == IP_HEADER_TCP) {
        puts("\n\n    TCP Header");
        puts("    =================");
        printf("    Source Port: ");
        print_port(tcp->source_port);
        printf("\n    Destination Port: ");
        print_port(tcp->dest_port);

        uint16_t tcp_header_len = (tcp->hlen_reserved_flags & 0xf0) >> 2;

        char* data_ptr = reinterpret_cast<char*>(tcp) + tcp_header_len;
        uint16_t data_len = ntohs(ip->ip_total_length) - ip_header_len - tcp_header_len;

        if(data_len > 0) {
            puts("\n\n    TCP Data");
            puts("    =================");
            printf("   ");
            for(int i = 0; i < data_len && i < 10; i++) printf(" %02X", data_ptr[i] & 0xff);
        }
      }
    }

    puts("");
  }

  pcap_close(handle);
  return 0;
}
