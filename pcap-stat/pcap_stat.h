#ifndef PCAP_STATS_H_
#define PCAP_STATS_H_

#include <arpa/inet.h>
#include <stdint.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include "pcap_stat.h"

#define likely(cond) (__builtin_expect(!!(cond), 1))
#define unlikely(cond) (__builtin_expect(!!(cond), 0))

void ParseCliArgs(int argc, char** argv, bool* is_endpoint,
                  bool* is_eth_based) {
  bool is_endpoint_chk = false;
  bool is_eth_based_chk = false;

  if (!strcmp(argv[1], "-h")) {
    std::cerr << "usage: ./pcap_stat <pcap_file> [options 1] [option 2]\n"
                 "options 1:\n"
                 "  -e    - endpoint statistics(default)\n"
                 "  -c    - converstation statistics\n"
                 "options 2:\n"
                 "  -m    - ethernet based statistics(default)\n"
                 "  -i    - IP based statistics\n";
    exit(1);
  }

  for (int i = 2; i < argc; i++) {
    if (argv[i][0] != '-' || strlen(argv[i]) != 2) {
      std::cerr << "invalid option: " << argv[i] << std::endl;
      exit(-1);
    }

    switch (argv[i][1]) {
      case 'e':
        if (is_endpoint_chk) {
          std::cerr << "duplicate option 1: " << argv[i] << std::endl;
          exit(-1);
        } else {
          *is_endpoint = true;
          is_endpoint_chk = true;
          break;
        }
      case 'c':
        if (is_endpoint_chk) {
          std::cerr << "duplicate option 1: " << argv[i] << std::endl;
          exit(-1);
        } else {
          *is_endpoint = false;
          is_endpoint_chk = true;
          break;
        }
      case 'm':
        if (is_eth_based_chk) {
          std::cerr << "duplicate option 2: " << argv[i] << std::endl;
          exit(-1);
        } else {
          *is_eth_based = true;
          is_eth_based_chk = true;
          break;
        }
      case 'i':
        if (is_eth_based_chk) {
          std::cerr << "duplicate option 2: " << argv[i] << std::endl;
          exit(-1);
        } else {
          *is_eth_based = false;
          is_eth_based_chk = true;
          break;
        }
      default:
        std::cerr << "invalid option: " << argv[1] << std::endl;
        exit(-1);
        break;
    }
  }

  return;
}

#pragma pack(push, 1)
struct MACAddr {
  uint8_t addr[6];

  bool operator<(const MACAddr& mac) const {
    for (int i = 0; i < 6; i++) {
      if (this->addr[i] != mac.addr[i]) {
        return this->addr[i] < mac.addr[i];
      }
    }
    return false;
  }

  bool operator==(const MACAddr& mac) const {
    for (int i = 0; i < 6; i++) {
      if (this->addr[i] != mac.addr[i]) {
        return false;
      }
    }
    return true;
  }

  friend std::ostream& operator<<(std::ostream& os, const MACAddr& mac) {
    os << std::setfill('0') << std::setw(2) << std::hex << (int)mac.addr[0];
    for (int i = 1; i < 6; i++) {
      os << ":" << (int)mac.addr[i];
    }
    os << std::dec;
    return os;
  }

  void set(const MACAddr& mac) {
    for (int i = 0; i < 6; i++) {
      this->addr[i] = mac.addr[i];
    }
  }
};

struct EthernetHeader {
  static constexpr uint16_t kEthernetTypeARP = 0x0806;
  static constexpr uint16_t kEthernetTypeIP = 0x0800;

  MACAddr dmac;
  MACAddr smac;
  uint16_t type;

  bool isARP() const {
    return ntohs(this->type) == EthernetHeader::kEthernetTypeARP;
  };

  bool isIPv4() const {
    return ntohs(this->type) == EthernetHeader::kEthernetTypeIP;
  };
};

struct IPv4Header {
  uint8_t ver_hlen;
  uint8_t tos;
  uint16_t total_len;

  uint16_t id;
  uint16_t frag_offset;

  uint8_t ttl;
  uint8_t protocol_id;
  uint16_t cksum;

  uint32_t s_ip;
  uint32_t d_ip;
};

struct TCPHeader {
  uint16_t s_port;
  uint16_t d_port;

  uint32_t seq;

  uint32_t ack;

  uint16_t hlen_with_flags;

  uint16_t wnd_size;
  uint16_t cksum;
  uint16_t urgent_ptr;
};

struct IPv4Packet {
  EthernetHeader eth_h;
  IPv4Header ip_h;

  MACAddr get_dmac() const { return this->eth_h.dmac; }
  MACAddr get_smac() const { return this->eth_h.smac; }
  uint32_t get_sip() const { return this->ip_h.s_ip; }
  uint32_t get_dip() const { return this->ip_h.d_ip; }
};
#pragma pack(pop)

struct KeyEndpoint {
  union key_entry {
    MACAddr mac;
    uint32_t ip;
  };

  bool isEthBased;
  key_entry key;

  bool operator<(const KeyEndpoint& k) const {
    if (this->isEthBased) {
      return this->get_mac() < k.get_mac();
    } else {
      return ntohl(this->get_ip()) < ntohl(k.get_ip());
    }
  }

  friend std::ostream& operator<<(std::ostream& os, const KeyEndpoint& key) {
    if (key.isEthBased) {
      os << key.key.mac;
      return os;
    } else {
      uint8_t ip[4];
      *(uint32_t*)ip = key.key.ip;

      os << (int)ip[0] << "." << (int)ip[1] << "." << (int)ip[2] << "."
         << (int)ip[3];
      return os;
    }
  }

  void set_key(const MACAddr& mac) {
    this->isEthBased = true;
    this->key.mac.set(mac);
  }

  void set_key(const uint32_t ip) {
    this->isEthBased = false;
    this->key.ip = ip;
  }

  MACAddr get_mac() const { return this->key.mac; }

  uint32_t get_ip() const { return this->key.ip; }
};

struct KeyConversation : KeyEndpoint {
  key_entry key_2;

  bool operator<(const KeyConversation& k) const {
    if (this->isEthBased) {
      return this->get_mac() == k.get_mac() ? this->key_2.mac < k.key_2.mac
                                            : this->get_mac() < k.get_mac();
    } else {
      return this->get_ip() != k.get_ip()
                 ? ntohl(this->get_ip()) < ntohl(k.get_ip())
                 : ntohl(this->key_2.ip) < ntohl(k.key_2.ip);
    }
  }

  friend std::ostream& operator<<(std::ostream& os,
                                  const KeyConversation& key) {
    if (key.isEthBased) {
      os << "(" << key.key.mac << ", " << key.key_2.mac << ")";
      return os;
    } else {
      uint8_t ip[4];

      *(uint32_t*)ip = key.key.ip;
      os << "(" << (int)ip[0] << "." << (int)ip[1] << "." << (int)ip[2] << "."
         << (int)ip[3] << ", ";

      *(uint32_t*)ip = key.key_2.ip;
      os << (int)ip[0] << "." << (int)ip[1] << "." << (int)ip[2] << "."
         << (int)ip[3] << ")";

      return os;
    }
  }

  // values in struct should be stored in consistent manner
  void set_key(const MACAddr& mac_1, const MACAddr& mac_2) {
    this->isEthBased = true;
    if (mac_1 < mac_2) {
      this->key.mac.set(mac_1);
      this->key_2.mac.set(mac_2);
    } else {
      this->key.mac.set(mac_2);
      this->key_2.mac.set(mac_1);
    }
  }

  // values in struct should be stored in consistent manner
  void set_key(const uint32_t ip_1, const uint32_t ip_2) {
    this->isEthBased = false;
    if (ntohl(ip_1) < ntohl(ip_2)) {
      this->key.ip = ip_1;
      this->key_2.ip = ip_2;
    } else {
      this->key.ip = ip_2;
      this->key_2.ip = ip_1;
    }
  }
};

struct StatsEntry {
  uint32_t packets;
  uint32_t bytes;

  uint32_t tx_packets;
  uint32_t tx_bytes;

  uint32_t rx_packets;
  uint32_t rx_bytes;

  void init() {
    this->packets = 0;
    this->bytes = 0;
    this->tx_packets = 0;
    this->tx_bytes = 0;
    this->rx_packets = 0;
    this->rx_bytes = 0;
  }
};

#endif  // PCAP_STATS_H_