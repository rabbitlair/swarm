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
 * @file Implementation of class Sniffer methods
 */

#include "sniffer.h"
using namespace std;

Sniffer* Sniffer::_instance = 0;

// Constructor: does nothing
Sniffer::Sniffer(void) {
  _handler = NULL;
  _initialized = false;
}

// Desctructor: close pcap session
Sniffer::~Sniffer(void) {
  pcap_close(_handler);
}

// Initialize interface, open sniffing session and apply packet filter
void Sniffer::start(string iface, string filter_str) {
  struct bpf_program filter;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  // Do not initialize twice
  if (_initialized) {
    return;
  }

  // Get ip address from selected interface
  _ip = getOwnIp(iface);

  // Create handler for sniffing
  _handler = pcap_create(iface.c_str(), (char*)_errbuf.c_str());
  if (_handler == NULL) {
    cerr << "ERROR - Couldn't open interface " << iface << ": ";
    cerr << _errbuf << endl;
    exit(EXIT_FAILURE);
  }

  // Actually start sniffing session
  pcap_activate(_handler);

  // Attempt to get network and netmask from interface
  if (pcap_lookupnet(iface.c_str(), &(net), &(mask),
      (char*)_errbuf.c_str()) == -1)
  {
    cerr << "ERROR - Can't get netmask for interface " << iface << endl;
    net = 0;
    mask = 0;
  }

  // Check link-layer type is supported (ethernet needed)
  if (pcap_datalink(_handler) != DLT_EN10MB) {
    cerr << "ERROR - Interface " << iface << " is not Ethernet device" << endl;
    exit(EXIT_FAILURE);
  }

  // Compile packet filter
  if (pcap_compile(_handler, &(filter), filter_str.c_str(), 0, net) == -1) {
    cerr << "ERROR - Couldn't parse filter " << filter_str << ": ";
    cerr << pcap_geterr(_handler) << endl;
    exit(EXIT_FAILURE);
  }

  // Apply compiled filter
  if (pcap_setfilter(_handler, &(filter)) == -1) {
    cerr << "ERROR - Couldn't install filter " << filter_str << ": ";
    cerr << pcap_geterr(_handler) << endl;
    exit(EXIT_FAILURE);
  }

  // Launch thread
  _initialized = true;
  thread t1(capture);
  t1.detach();
}

// Parse information from an ARP request packet
void Sniffer::processArp(const u_char* packet) {
  // Dummy variable to check ip address validity
  struct sockaddr_in sa;
  Device dev;

  // Get ARP header
  struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ethhdr));

  // If ARP packet is response extract all data
  if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
    // Buffer to convert from integer to string, MAC formatted
    stringstream ss_mac;

    // Buffer to convert from integer to string
    stringstream ss_ip;

    // Struct to store MAC address
    struct ether_addr* mac_addr;

    // Get source MAC address
    mac_addr = (ether_addr*)arp->arp_sha;
    for (int i = 0; i < 5; ++i) {
      ss_mac << setfill('0') << setw(2) << uppercase << hex;
      ss_mac << (int)mac_addr->ether_addr_octet[i] << ":";
    }
    ss_mac << setfill('0') << setw(2) << uppercase << hex;
    ss_mac << (int)mac_addr->ether_addr_octet[5];
    string sha = ss_mac.str();

    // If mac address has been already processed, do nothing
    if (_macs_processed.find(sha) != _macs_processed.end()) {
      return;
    }

    // Reset stringstream
    ss_mac.str(string());
    ss_mac.clear();

    // Get source IP address
    for (int i = 0; i < 4; ++i) {
      ss_ip << (int)arp->arp_spa[i];
      ss_ip << ((i != 3) ? "." : "");
    }
    string spa = ss_ip.str();

    // Reset stringstream
    ss_ip.str(string());
    ss_ip.clear();

    // Check ip address validity
    if (inet_pton(AF_INET, spa.c_str(), &(sa.sin_addr)) > 0) {
      // Do not store own ip address
      if (spa.c_str() != sniffer->getIp()) {
        // If device is not registered, save it
        try {
          dev = monitor->getDevice(spa);
        }
        catch (exception) {
          dev.setIp(spa);
          monitor->addDevice(dev);
        }

        // Update MAC address of corresponding device
        dev.setMac(sha);
        if (monitor->updateDevice(spa, dev)) {
          cerr << "ERROR - Can't update device with ip " << spa << endl;
        }

        // Add mac address to processed macs list
        _macs_processed.insert(sha);
      }
    }
    // No need to process target MAC address, as it's our own mac
  }
}

// TODO Implement VLAN stripping
// Parse information from VLAN tagged packet
void Sniffer::processVlan(const u_char* packet) {
  cout << "VLAN" << endl;
}

// Parse information from ICMP response packet
void Sniffer::processIcmp(const u_char* packet, const string& src) {
  Device dev;
  string address;
  bool reachable = false;

  // Get ip header
  struct iphdr* iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
  // Move packet pointer, skipping layer 2 header and layer 3 packet
  u_char* icmp = (u_char*)packet + sizeof(struct ethhdr) + (iph->ihl * 4);
  // Get layer 4 header: in this case, it's ICMP header
  struct icmphdr* icmphdr = (struct icmphdr*)icmp;

  // Get ip address to evaluate
  // Echo reply is received, then device is reachable
  if (icmphdr->type == ICMP_ECHOREPLY) {
    address = src;
    reachable = true;
  }
  // Received host unreachable packet, so device is unreachable
  else if (icmphdr->type == ICMP_DEST_UNREACH) {
    // Get full icmp packet
    struct icmp* icmp_pkt = (struct icmp*)(icmp);
    // Get destination ip address from original ip header
    address = string(inet_ntoa(icmp_pkt->icmp_dun.id_ip.idi_ip.ip_dst));
  }
  // No need to process any other icmp types
  else {
    return;
  }

  // If reachability has been already processed, do nothing
  if (_reachability_processed.find(address) != _reachability_processed.end()) {
    return;
  }

  // If device is not registered, discard it
  // Else, update reachability of device
  try {
    dev = monitor->getDevice(address);
    dev.setReachable(reachable);
    if (monitor->updateDevice(address, dev)) {
      cerr << "ERROR - Can't update device with ip " << address << endl;
    }
    // Avoid processing same host reachability more than once
    _reachability_processed.insert(address);
  }
  catch (exception) {
    return;
  }
}

// Pcap session handler getter
pcap_t* Sniffer::getHandler(void) const {
  return _handler;
}

// Own ip address getter
const string& Sniffer::getIp(void) const {
  return _ip;
}

// Checks if some arbitrary ip address is private, according to IANA
bool Sniffer::ipIsPrivate(const string& ip) const {
  struct sockaddr_in sa;

  // Check ip address validity
  if (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) > 0) {
    uint32_t address = *((uint32_t*)&(sa.sin_addr));

    // Private ip address, class A
    if ((address & 0x000000FFU) == 0x0000000AU) {
      // Discard broadcast address for class A
      return (address != 0xFFFFFF0AU);
    }

    // Private ip address, class B
    if ((address & 0x0000F0FFU) == 0x000010ACU) {
      // Discard broadcast address for class B
      return (address != 0xFFFF1FACU);
    }

    // Private ip address, class C
    if ((address & 0x0000FFFFU) == 0x0000A8C0U) {
      // Discard broadcast address for class C
      return (address != 0xFFFFA8C0U);
    }
  }
  return false;
}

// Get ip address from some interface name
string Sniffer::getOwnIp(const string& name) const {
  struct ifaddrs *ifaddr, *ifa;
  string ip;

  // Get all network interfaces of this system
  if (getifaddrs(&ifaddr) == -1) {
    cerr << "ERROR - Unable to get ip address of interface " << name << endl;
    exit(EXIT_FAILURE);
  }

  // For each found interface, check if it's the one we are looking for
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) {
      continue;
    }

    // Save asked interface's ip address
    if (strcmp(ifa->ifa_name, name.c_str()) == 0) {
      if (ifa->ifa_addr->sa_family == AF_INET) {
        ip = inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr);
      }
    }
  }

  // Free all interfaces info, as it's no longer needed
  freeifaddrs(ifaddr);
  return ip;
}

