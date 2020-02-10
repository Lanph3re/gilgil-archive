#include <pcap.h>
#include <iostream>
#include <map>
#include <sstream>
#include "pcap_stat.h"

using namespace std;

int main(int argc, char** argv) {
  if (argc < 2) {
    cerr << "usage: ./pcap_stat [-h] <pcap_file> [options 1] [option 2]\n"
            "  -h    - usage info\n"
            "options 1:\n"
            "  -e    - endpoint statistics(default)\n"
            "  -c    - converstation statistics\n"
            "options 2:\n"
            "  -m    - ethernet based statistics(default)\n"
            "  -i    - IP based statistics\n";
    exit(-1);
  }

  bool is_endpoint = true;
  bool is_eth_based = true;
  ParseCliArgs(argc, argv, &is_endpoint, &is_eth_based);

  pcap_t* handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  handle = pcap_open_offline(argv[1], errbuf);
  if (handle == nullptr) {
    cerr << "pcap_open_offline() failed: " << errbuf << endl;
    exit(-1);
  }

  if (is_endpoint) {
    // endpoint statistics
    const u_char* pkt = nullptr;
    pcap_pkthdr* pkt_header = nullptr;
    map<KeyEndpoint, StatsEntry> pstats;

    // iterate through packets in .pcap file
    while (true) {
      int res = pcap_next_ex(handle, &pkt_header, &pkt);

      if (unlikely(res == -2)) {
        break;
      }

      EthernetHeader* eth_p =
          reinterpret_cast<EthernetHeader*>(const_cast<u_char*>(pkt));

      // only considers IP packets
      if (unlikely(eth_p->isARP())) {
        continue;
      }

      IPv4Packet* pkt_p = reinterpret_cast<IPv4Packet*>(eth_p);
      KeyEndpoint key1, key2;

      if (is_eth_based) {
        key1.set_key(pkt_p->get_dmac());
        key2.set_key(pkt_p->get_smac());
      } else {
        key1.set_key(pkt_p->get_dip());
        key2.set_key(pkt_p->get_sip());
      }

      // update entry corresponding to key1
      auto entry = pstats.find(key1);
      StatsEntry stats_entry;

      if (likely(entry != pstats.end())) {
        stats_entry = (*entry).second;
      } else {
        stats_entry.init();
      }

      bool is_rx;
      if (is_eth_based) {
        is_rx = key1.get_mac() == pkt_p->get_dmac();
      } else {
        is_rx = key1.get_ip() == pkt_p->get_dip();
      }

      stats_entry.packets++;
      stats_entry.bytes += pkt_header->len;
      if (!is_rx) {
        stats_entry.tx_packets++;
        stats_entry.tx_bytes += pkt_header->len;
      } else {
        stats_entry.rx_packets++;
        stats_entry.rx_bytes += pkt_header->len;
      }

      pstats[key1] = stats_entry;

      // update entry corresponding to key2
      entry = pstats.find(key2);

      if (likely(entry != pstats.end())) {
        stats_entry = (*entry).second;
      } else {
        stats_entry.init();
      }

      if (is_eth_based) {
        is_rx = key2.get_mac() == pkt_p->get_dmac();
      } else {
        is_rx = key2.get_ip() == pkt_p->get_dip();
      }

      stats_entry.packets++;
      stats_entry.bytes += pkt_header->len;
      if (!is_rx) {
        stats_entry.tx_packets++;
        stats_entry.tx_bytes += pkt_header->len;
      } else {
        stats_entry.rx_packets++;
        stats_entry.rx_bytes += pkt_header->len;
      }

      pstats[key2] = stats_entry;
    }

    // print statistics info
    cout.setf(ios::left);
    cout << setw(20) << "Address";
    cout << "|" << setw(10) << "Packets";
    cout << "|" << setw(10) << "Bytes";
    cout << "|" << setw(10) << "Tx Packets";
    cout << "|" << setw(10) << "Tx Bytes";
    cout << "|" << setw(10) << "Rx Packets";
    cout << "|" << setw(10) << "Rx Bytes" << endl;
    cout.setf(ios::right);

    for (auto iter = pstats.begin(); iter != pstats.end(); iter++) {
      ostringstream stream;
      StatsEntry tmp = (*iter).second;

      stream << (*iter).first;
      cout << setw(20) << stream.str();
      cout << "|" << setw(10) << tmp.packets;
      cout << "|" << setw(10) << tmp.bytes;
      cout << "|" << setw(10) << tmp.tx_packets;
      cout << "|" << setw(10) << tmp.tx_bytes;
      cout << "|" << setw(10) << tmp.rx_packets;
      cout << "|" << setw(10) << tmp.rx_bytes << endl;
    }
  } else {
    // conversation statistics
    const u_char* pkt;
    pcap_pkthdr* pkt_header;
    map<KeyConversation, StatsEntry> pstats;

    // iterate through packets in .pcap file
    while (true) {
      int res = pcap_next_ex(handle, &pkt_header, &pkt);

      if (unlikely(res == -2)) {
        break;
      }

      EthernetHeader* eth_p =
          reinterpret_cast<EthernetHeader*>(const_cast<u_char*>(pkt));

      // only considers IP packets
      if (unlikely(eth_p->isARP())) {
        continue;
      }

      IPv4Packet* pkt_p = reinterpret_cast<IPv4Packet*>(eth_p);
      KeyConversation key;

      if (is_eth_based) {
        key.set_key(pkt_p->get_dmac(), pkt_p->get_smac());
      } else {
        key.set_key(pkt_p->get_dip(), pkt_p->get_sip());
      }

      auto entry = pstats.find(key);
      StatsEntry stats_entry;

      if (likely(entry != pstats.end())) {
        stats_entry = (*entry).second;
      } else {
        stats_entry.init();
      }

      bool is_rx;
      if (is_eth_based) {
        is_rx = key.get_mac() == pkt_p->get_dmac();
      } else {
        is_rx = key.get_ip() == pkt_p->get_dip();
      }

      stats_entry.packets++;
      stats_entry.bytes += pkt_header->len;
      if (!is_rx) {
        stats_entry.tx_packets++;
        stats_entry.tx_bytes += pkt_header->len;
      } else {
        stats_entry.rx_packets++;
        stats_entry.rx_bytes += pkt_header->len;
      }

      pstats[key] = stats_entry;
    }

    // print statistics info
    cout.setf(ios::left);
    cout << setw(38) << "Address(A, B)";
    cout << "|" << setw(10) << "Packets";
    cout << "|" << setw(10) << "Bytes";
    cout << "|" << setw(12) << "Packets A->B";
    cout << "|" << setw(12) << "Bytes A->B";
    cout << "|" << setw(12) << "Packets B->A";
    cout << "|" << setw(12) << "Bytes B->A" << endl;
    cout.setf(ios::right);

    for (auto iter = pstats.begin(); iter != pstats.end(); iter++) {
      ostringstream stream;
      StatsEntry tmp = (*iter).second;

      stream << (*iter).first;
      cout << setw(38) << stream.str();
      cout << "|" << setw(10) << tmp.packets;
      cout << "|" << setw(10) << tmp.bytes;
      cout << "|" << setw(12) << tmp.tx_packets;
      cout << "|" << setw(12) << tmp.tx_bytes;
      cout << "|" << setw(12) << tmp.rx_packets;
      cout << "|" << setw(12) << tmp.rx_bytes << endl;
    }
  }

  return 0;
}