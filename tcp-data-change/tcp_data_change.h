#ifndef TCP_DAT_CHG_H_
#define TCP_DAT_CHG_H_

#include "tcp_data_change.h"
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct StreamKey {
  uint32_t ip_1;
  uint32_t ip_2;
  uint16_t port_1;
  uint16_t port_2;

  bool operator<(const StreamKey &key) const {
	  return this->ip_1 != key.ip_1 ? this->ip_1 < key.ip_1
		  			: this->ip_2 < key.ip_2;
  }

  StreamKey(struct iphdr *ip, struct tcphdr *tcp) {
    if (ip->saddr < ip->daddr) {
      this->ip_1 = ip->saddr;
      this->ip_2 = ip->daddr;
      this->port_1 = tcp->source;
      this->port_2 = tcp->dest;
    } else {
      this->ip_1 = ip->daddr;
      this->ip_2 = ip->saddr;
      this->port_1 = tcp->dest;
      this->port_2 = tcp->source;
    }
  }
};

struct StreamEntry {
  uint32_t packets;
  uint32_t bytes;

  uint32_t tx_packets;
  uint32_t tx_bytes;

  uint32_t rx_packets;
  uint32_t rx_bytes;

  uint32_t trace_off_1; // ep1 -> ep2
  uint32_t trace_off_2; // ep2 -> ep1

  StreamEntry() {
    this->packets = 0;
    this->bytes = 0;
    this->tx_packets = 0;
    this->tx_bytes = 0;
    this->rx_packets = 0;
    this->rx_bytes = 0;
    this->trace_off_1 = 0;
    this->trace_off_2 = 0;
  }
};

#endif  // TCP_DAT_CHG_H_

