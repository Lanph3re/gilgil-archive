#ifndef ARP_H_
#define ARP_H_

#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthernetHeader
{
  static const uint16_t ETHERNET_TYPE_ARP = 0x0806;

  uint8_t dmac[6];
  uint8_t smac[6];
  uint16_t type;

  bool isBroadcast() const
  {
    for (int i = 0; i < 6; i++) {
      if (this->dmac[i] != 0xff) {
        return false;
      }
    }

    return true;
  };

  bool isARP() const
  {
    return ntohs(this->type) == EthernetHeader::ETHERNET_TYPE_ARP;
  };
};

struct ArpHeader
{
  static const uint16_t ARP_H_ETHERNET = 0x1;
  static const uint16_t ARP_H_IPV4 = 0x0800;
  static const uint8_t ARP_H_HW_SIZE = 0x6;
  static const uint8_t ARP_H_PROTOCOL_SIZE = 0x4;

  static const uint16_t ARP_H_REQUEST = 0x1;
  static const uint16_t ARP_H_REPLY = 0x2;

  uint16_t hw_type;
  uint16_t protocol;

  uint8_t hw_size;
  uint8_t protocol_size;
  uint16_t opcode;

  uint8_t smac[6];
  uint8_t s_ip[4];
  uint8_t dmac[6];
  uint8_t d_ip[4];

  bool isRequest() const
  {
    return ntohs(this->opcode) == ArpHeader::ARP_H_REQUEST;
  };

  bool isReply() const
  {
    return ntohs(this->opcode) == ArpHeader::ARP_H_REPLY;
  };
};

struct ArpMsg
{
  EthernetHeader eth_header;
  ArpHeader arp_header;
  uint8_t padding[0x12];
};

struct IPv4Header
{
  uint8_t ver_and_header_len;
  uint8_t tos;
  uint16_t total_length;

  uint16_t identifier;
  uint16_t fragment_offset;

  uint8_t time_to_lve;
  uint8_t protocol_id;
  uint16_t checksum;

  uint8_t source_addr[4];
  uint8_t dest_addr[4];
};

struct Packet
{
  EthernetHeader eth_header;
  IPv4Header ipv4_header;
};
#pragma pack(pop)

void
ReadIP(uint8_t ip_addr[4], const char* address);

void
GetInterfaceInfo(const char* ifname, uint8_t mac_addr[6], uint8_t ip_addr[4]);
void
PrintMac(const char* info_name, uint8_t mac_addr[6]);
void
PrintIP(const char* info_name, uint8_t ip_addr[4]);

bool
SendArpMsg(pcap_t* pcap,
           uint8_t src_mac[6],
           uint8_t src_ip[6],
           uint8_t dst_mac[6],
           uint8_t dst_ip[4],
           uint16_t opcode);

#endif