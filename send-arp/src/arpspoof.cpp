#include "arpspoof.hpp"
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>

extern uint8_t sender_mac_addr[4];

void parse_ioctl(const char *ifname, uint8_t mac_addr[6], uint8_t ip_addr[4]) {
  int sock;
  struct ifreq ifr;
  struct sockaddr_in *ipaddr;
  char address[INET_ADDRSTRLEN];
  size_t ifnamelen;

  // Copy ifname to ifr object
  ifnamelen = strlen(ifname);

  if (ifnamelen >= sizeof(ifr.ifr_name)) {
    puts("Too long interface name");
    exit(-1);
  }

  strcpy(ifr.ifr_name, ifname);

  // Open a socket
  sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock < 0) {
    puts("Failed to open a socket");
    exit(-1);
  }

  // Process MAC address
  if (ioctl(sock, SIOCGIFHWADDR, &ifr) != -1) {
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
  }

  // Die if failed to get an IP address
  if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
    close(sock);

    return;
  }

  // Process IP address
  ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
  if (inet_ntop(AF_INET, &ipaddr->sin_addr, address, sizeof(address)) != NULL) {
    *(uint32_t *)ip_addr = inet_addr(address);
  }

  return;
}

void print_mac(const char *info_name, uint8_t mac_addr[6]) {
  printf("[*] %s: %02X:%02X:%02X:%02X:%02X:%02X\n", info_name, mac_addr[0],
         mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
}

void print_ip(const char *info_name, uint8_t ip_addr[4]) {
  printf("[*] %s: %u.%u.%u.%u\n", info_name, ip_addr[0], ip_addr[1], ip_addr[2],
         ip_addr[3]);
}

void send_arp_packet(pcap_t *pcap, uint8_t src_mac[6], uint8_t src_ip[4],
                     uint8_t dst_mac[6], uint8_t dst_ip[4], uint16_t opcode) {
  Arp_Message msg;

  // ARP Request: Broadcast
  // ARP Reply: Unicast
  if (opcode == ARP_REQUEST) {
    memset(msg.eth_header.dmac, 0xFF, 6);
  } else {
    memcpy(msg.eth_header.dmac, dst_mac, 6);
  }

  memcpy(msg.eth_header.smac, src_mac, 6);
  msg.eth_header.type = htons(ETH_TYPE_ARP);

  msg.arp_header.hw_type = htons(ETHERNET);
  msg.arp_header.protocol = htons(IPV4);
  msg.arp_header.hw_size = HW_SIZE;
  msg.arp_header.protocol_size = PROTOCOL_SIZE;
  msg.arp_header.opcode = htons(opcode);
  memcpy(msg.arp_header.smac, src_mac, 6);
  memcpy(msg.arp_header.s_ip, src_ip, 4);

  // ARP Request
  // DMAC: 00:00:00:00:00:00
  if (opcode == ARP_REQUEST) {
    memset(msg.arp_header.dmac, 0, 6);
  } else {
    memcpy(msg.arp_header.dmac, dst_mac, 6);
  }

  memcpy(msg.arp_header.d_ip, dst_ip, 4);
  memset(msg.padding, 0, 0x12);

  /* Send down the packet */
  if (pcap_sendpacket(pcap, (u_char *)&msg, 100) != 0) {
    fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pcap));
    exit(-1);
  }

  return;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                    const u_char *pkt_data) {
  memcpy(sender_mac_addr, ((Ethernet_Header *)pkt_data)->smac, 6);
}
