#ifndef SESSION_H_
#define SESSION_H_

#include "arpspoof.h"

void
ArpSpoof(const char* ifname, const char* sender_ip, const char* target_ip);

#endif