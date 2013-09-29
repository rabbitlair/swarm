/**
 * Copyright 2013 Ezequiel Vázquez De la calle
 *
 * This file is part of Swarm.
 *
 * Swarm is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Swarm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file Action functions implementation
 */

#include "actions.h"
using namespace std;

// Packet captured callback, using libpcap
void gotPacket(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
  // Get ethernet header
  struct ethhdr *eth = (struct ethhdr *)packet;

  // Process 802.1Q VLAN tagging to guess in which VLAN lives some device
  if (ntohs(eth->h_proto) == ETHERTYPE_VLAN) {
    sniffer->processVlan(packet);
  }

  // Process ARP protocol to obtain MAC address relative to some IP
  // ARP protocol has no ip payload, so exit after processing
  if (ntohs(eth->h_proto) == ETHERTYPE_ARP) {
    sniffer->processArp(packet);
    return;
  }

  // Get ip header
  struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

  // Extract source and destination ip addresses
  in_addr source, destination;
  source.s_addr = iph->saddr;
  destination.s_addr = iph->daddr;

  // Store ip addresses as new devices, or discard if has been registered yet
  string src = string(inet_ntoa(source));
  string dst = string(inet_ntoa(destination));

  // This is a dummy variable needed for ip validity checks
  struct sockaddr_in sa;

  // Check source ip address validity
  if (inet_pton(AF_INET, src.c_str(), &(sa.sin_addr)) > 0) {
    // Store source ip address if it's not saved yet, and it's private
    if (sniffer->ipIsPrivate(src) && not monitor->checkDevice(src)) {
      // Do not store own ip address
      if (src != sniffer->getIp() and src != sniffer->getSpoofIp()) {
        Device dev = Device(src);
        monitor->addDevice(dev);
      }
    }
  }

  // Check destination ip address validity
  if (inet_pton(AF_INET, dst.c_str(), &(sa.sin_addr)) > 0) {
    // Store destination ip address if it's not saved yet, and it's private
    if (sniffer->ipIsPrivate(dst) and not monitor->checkDevice(dst)) {
      // Do not store own ip address, or spoofed
      if (dst != sniffer->getIp() and dst != sniffer->getSpoofIp()) {
        Device dev = Device(dst);
        monitor->addDevice(dev);
      }
    }
  }

  // Use spoofed ip as own ip address, if defined
  string ip = sniffer->getIp();
  if (not sniffer->getSpoofIp().empty()) {
    ip = sniffer->getSpoofIp();
  }

  // Use ICMP packets to guess device reachability
  // As we want to know reachability from our device, only icmp packets with
  // our ip address as destination one are needed
  if (iph->protocol == 1 && dst == ip) {
    sniffer->processIcmp(packet, src);
  }
}

// Capture action
void capture(void) {
  pcap_loop(sniffer->getHandler(), -1, gotPacket, NULL);
}

// Inject action
void inject(void) {
  Device dev;

  // Race condition avoid: there must be, at least, one detected device
  while (monitor->count() == 0) {
    sleep(1);
  }

  // Start on first device on monitor
  monitor->reset();

  // Iterate over monitor stored devices, and try to guess empty attributes
  while (1) {
    dev = monitor->getCurrent();

    // If current device has not MAC address registered, launch ARP request
    if (dev.getMac().empty()) {
      injector->injectArpRequest(dev.getIp());
    }

    // Check reachability, if it has not been checked.
    if (dev.getReachable() == -1) {
      if (dev.getMac().empty()) {
        injector->injectIcmp(dev.getIp(), "FF:FF:FF:FF:FF:FF");
      }
      else {
        injector->injectIcmp(dev.getIp(), dev.getMac());
      }
    }

    // If performing IP spoofing, poison current device
    if (not dev.getMac().empty() and not injector->getSpoofIp().empty()) {
      injector->injectArpSpoofResponse(dev.getIp(), dev.getMac());
    }

    // Advance to next device inside monitor
    monitor->next();
  }
}

