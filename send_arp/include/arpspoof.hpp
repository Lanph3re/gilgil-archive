#pragma once

#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>

#define ETH_TYPE_ARP 0x0806

typedef struct {
  uint8_t dmac[6];
  uint8_t smac[6];
  uint16_t type;
} Ethernet_Header;

// Values in ARP Header
#define ETHERNET 1
#define IPV4 0x0800
#define HW_SIZE 6
#define PROTOCOL_SIZE 4

#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct {
  uint16_t hw_type;
  uint16_t protocol;

  uint8_t hw_size;
  uint8_t protocol_size;

  uint16_t opcode;

  uint8_t smac[6];
  uint8_t s_ip[4];

  uint8_t dmac[6];
  uint8_t d_ip[4];
} Arp_Header;

typedef struct {
  Ethernet_Header eth_header;
  Arp_Header arp_header;
  uint8_t padding[0x12];
} Arp_Message;

void parse_ioctl(const char *ifname, uint8_t mac_addr[6], uint8_t ip_addr[4]);
void print_mac(const char *info_name, uint8_t mac_addr[6]);
void print_ip(const char *info_name, uint8_t ip_addr[4]);

void send_arp_packet(pcap_t *pcap, uint8_t src_mac[6], uint8_t src_ip[6],
                     uint8_t dst_mac[6], uint8_t dst_ip[4], uint16_t opcode);

void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                    const u_char *pkt_data);