#include <linux/netfilter.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <array>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include "tcp_data_change.h"

extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>
}

#define THROW_IF_TRUE(x, m)        \
  do {                             \
    if ((x)) {                     \
      throw std::runtime_error(m); \
    }                              \
  } while (false)

#define CONCAT_0(pre, post) pre##post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)

using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;

#define SCOPED_GUARD_NAMED(name, code)            \
  ScopedGuard name(reinterpret_cast<void *>(-1),  \
                   [&](void *) -> void { code }); \
  (void)name

#define SCOPED_GUARD(code) \
  SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code)

struct pkt_buff {
  uint8_t *mac_header;
  uint8_t *network_header;
  uint8_t *transport_header;

  uint8_t *head;
  uint8_t *data;
  uint8_t *tail;

  uint32_t len;
  uint32_t data_len;

  bool mangled;
};

static char *from_string;
static char *to_string;
static uint32_t from_len;
static uint32_t to_len;
static int len_diff;

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg,
                             struct nfq_data *nfad, void *data) {
  // stream_manager stores stream info and manages offset diffs
  static std::map<StreamKey, StreamEntry> stream_manager;

  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
  THROW_IF_TRUE(ph == nullptr, "Issue while packet header");

  uint8_t *rawData = nullptr;
  int len = nfq_get_payload(nfad, &rawData);
  THROW_IF_TRUE(len < 0, "Can\'t get payload data");

  struct pkt_buff *pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
  THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate");
  SCOPED_GUARD(pktb_free(pkBuff););

  struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
  THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header parse.");

  THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0,
                "Can\'t set transport header.");

  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = nfq_tcp_get_hdr(pkBuff);
    THROW_IF_TRUE(tcp == nullptr, "Issue while tcp header.");

    void *payload = nfq_tcp_get_payload(tcp, pkBuff);
    unsigned int payloadLen = nfq_tcp_get_payload_len(tcp, pkBuff);
    payloadLen -= 4 * tcp->th_off;
    THROW_IF_TRUE(payload == nullptr, "Issue while payload.");

    // manipulate seq/ack number
    StreamKey key(ip, tcp);

    auto entry = stream_manager.find(key);
    if (entry != stream_manager.end()) {
      std::cout << "[*] trace offs" << std::endl;
      std::cout << (*entry).second.trace_off_1 << std::endl;
      std::cout << (*entry).second.trace_off_2 << std::endl;

      if (ip->saddr == key.ip_1) {
        // forward stream
        tcp->seq += entry->second.trace_off_1;
        tcp->ack_seq -= entry->second.trace_off_2;
      } else {
        // backward stream
        tcp->seq += entry->second.trace_off_2;
        tcp->ack_seq -= entry->second.trace_off_1;
      }
    }

    void *find_ptr = payload;
    uint32_t find_len = payloadLen;
    int len_off = 0;

    while (find_ptr = memmem(find_ptr, find_len, from_string, from_len)) {
      uint32_t match_off = reinterpret_cast<uint8_t *>(find_ptr) -
                           reinterpret_cast<uint8_t *>(payload);
      nfq_tcp_mangle_ipv4(pkBuff, match_off, from_len, to_string, to_len);

      find_ptr =
          reinterpret_cast<void *>(reinterpret_cast<uint8_t *>(find_ptr) + 1);
      find_len = pkBuff->tail - reinterpret_cast<uint8_t *>(find_ptr);

      len_off += len_diff;
    }

    // trace offset info using map
    if (entry != stream_manager.end()) {
      StreamEntry &se = entry->second;
      se.packets++;
      se.bytes += len;

      if (ip->saddr == key.ip_1) {
        se.tx_packets++;
        se.tx_bytes += len;
        se.trace_off_1 += len_off;
      } else {
        se.rx_packets++;
        se.rx_bytes += len;
        se.trace_off_2 += len_off;
      }
    } else {
      StreamEntry se;
      se.packets++;
      se.bytes += len;

      if (ip->saddr == key.ip_1) {
        se.tx_packets++;
        se.tx_bytes += len;
        se.trace_off_1 = len_off;
      } else {
        se.rx_packets++;
        se.rx_bytes += len;
        se.trace_off_2 = len_off;
      }

      stream_manager.insert(std::make_pair(key, se));
    }

    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT,
                           pktb_len(pkBuff), pktb_data(pkBuff));
  }
  return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}

int main(int argc, char **argv) {
  if (argc < 3) {
    std::cerr << "usage: tcp_data_change <from string> <to string>";
    exit(-1);
  }

  from_string = argv[1];
  from_len = strlen(from_string);
  to_string = argv[2];
  to_len = strlen(to_string);
  len_diff = to_len - from_len;
  THROW_IF_TRUE(strcmp(from_string, to_string) == 0,
                "Both strings are the same.");

  struct nfq_handle *handler = nfq_open();
  THROW_IF_TRUE(handler == nullptr, "Can\'t open hfqueue handler.");
  SCOPED_GUARD(nfq_close(handler););

  struct nfq_q_handle *queue =
      nfq_create_queue(handler, 0, netfilterCallback, nullptr);
  THROW_IF_TRUE(queue == nullptr, "Can\'t create queue handler.");
  SCOPED_GUARD(nfq_destroy_queue(queue););

  THROW_IF_TRUE(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0,
                "Can\'t set queue copy mode.");

  int fd = nfq_fd(handler);
  std::array<char, 0x10000> buffer;

  for (;;) {
    int len = recv(fd, buffer.data(), buffer.size(), 0);
    THROW_IF_TRUE(len < 0, "Issue while read");
    nfq_handle_packet(handler, buffer.data(), len);
  }

  return 0;
}
