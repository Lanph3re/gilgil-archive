#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H
#include <stdint.h>

#define ETHER_ADDR_LEN 6
#define ETHER_TYPE_IP 0x0800

typedef struct EthernetHeader {
  uint8_t dest[6];
  uint8_t src[6];
  uint16_t type;
} EthernetHeader, *EthernetHeaderPtr;

#define IP_HEADER_TCP 6

typedef struct IPHeader {
  uint8_t ip_version_header_length;
  uint8_t ip_tos;
  uint16_t ip_total_length;

  uint16_t ip_id;
  uint16_t ip_flags_frag_offset;

  uint8_t ip_ttl;
  uint8_t ip_protocol;
  uint16_t ip_checksum;

  uint8_t ip_srcaddr[4];
  uint8_t ip_destaddr[4];
} IPHeader, *IPHeaderPtr;

#define HTTP_PORT 80

typedef struct TCPHeader {
  uint16_t source_port;
  uint16_t dest_port;

  uint32_t sequence;

  uint32_t acknowledge;

  uint16_t hlen_reserved_flags;

  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_pointer;
} TCPHeader, *TCPHeaderPtr;

void print_mac(uint8_t *mac);
void print_ip(uint8_t *ip);
void print_port(uint16_t port);

uint16_t ntohs(uint16_t x);

#endif // PACKET_HEADERS_H
