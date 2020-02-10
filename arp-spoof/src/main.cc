#include "arpspoof.h"
#include "session.h"
#include <iostream>
#include <string>
#include <thread>

using namespace std;

#define WAIT(x) sleep((x))

uint8_t mac_addr[6];
uint8_t ip_addr[4];

bool run;

int
main(int argc, char* argv[])
{
  if (argc < 4) {
    cout << "Usage: arp_spoof <interface> <sender ip> <target ip> .." << endl;
    return 0;
  }

  if (argc & 1) {
    cout << "No corresponding target ip of " << argv[argc - 1] << endl;
    return 0;
  }

  GetInterfaceInfo(argv[1], mac_addr, ip_addr);
  PrintMac("MAC address", mac_addr);
  PrintIP("IP address", ip_addr);

  // Create ARP spoofing sessions
  run = true;
  int num_session = (argc - 2) >> 1;

  for (int i = 0; i < num_session; i++) {
    thread new_session{ ArpSpoof, argv[1], argv[i * 2 + 2], argv[i * 2 + 3] };
    new_session.detach();
  }

  // Terminate sessions
  string cmd;

  WAIT(8);
  while (true) {
    cin >> cmd;

    if (!cmd.compare("quit")) {
      run = false;
      break;
    }
  }

  return 0;
}