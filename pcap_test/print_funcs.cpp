#include <cstdio>
#include <stdint.h>
#include "packet_headers.h"

void print_mac(uint8_t *mac) {
  for (int i = 0; i < ETHER_ADDR_LEN; i++) {
    if (i != 0) printf(":");
    printf("%02X", mac[i]);
  }
}

void print_ip(uint8_t *ip) {
  printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint16_t port) {
  printf("%u", ntohs(port));
}

uint16_t ntohs(uint16_t x) {
    return static_cast<uint16_t>(x >> 8 | x << 8);
}
