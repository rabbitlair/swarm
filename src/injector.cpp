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
 * @file Class Injector method definition
 */

#include "injector.h"
using namespace std;

Injector* Injector::_instance = 0;

// Constructor
Injector::Injector(void) {
  _handler = NULL;
  _initialized = false;
  _eth_arp_tag = LIBNET_PTAG_INITIALIZER;
  _arp_tag = LIBNET_PTAG_INITIALIZER;
  _eth_ip_tag = LIBNET_PTAG_INITIALIZER;
  _ip_tag = LIBNET_PTAG_INITIALIZER;
  _icmp_tag = LIBNET_PTAG_INITIALIZER;
}

// Destructor
Injector::~Injector(void) {
  libnet_destroy(_handler);
}

// Initialize injector object, and launch as thread
void Injector::start(string iface) {
  string errbuf;

  // Do not initialize twice
  if (_initialized) {
    return;
  }

  // Initialize libnet handler
  _handler = libnet_init(LIBNET_LINK, (char*)iface.c_str(),
      (char*)errbuf.c_str());
  if (_handler == NULL) {
    cerr << "ERROR - Libnet couldn't be initialized" << endl;
    cerr << errbuf << endl;
    exit(EXIT_FAILURE);
  }

  // Get own ip address from libnet handler
  u_int32_t ip_addr = libnet_get_ipaddr4(_handler);
  if (ip_addr < 0) {
    cerr << "ERROR - libnet can not determine ip address for interface ";
    cerr << iface << endl << libnet_geterror(_handler) << endl;
    exit(EXIT_FAILURE);
  }

  // Save own ip address to private attribute
  _ip = libnet_addr2name4(ip_addr, LIBNET_DONT_RESOLVE);

  // Get own mac address from libnet handler
  struct libnet_ether_addr* mac_addr = libnet_get_hwaddr(_handler);
  if (mac_addr == NULL) {
    cerr << "ERROR - libnet can not determine mac address for interface ";
    cerr << iface << endl << libnet_geterror(_handler) << endl;
    exit(EXIT_FAILURE);
  }

  // Save own mac address to private attribute
  stringstream ss;
  for (int i = 0; i < 5; ++i) {
    ss << setfill('0') << setw(2) << uppercase << hex;
    ss << (int)mac_addr->ether_addr_octet[i] << ":";
  }
  ss << setfill('0') << setw(2) << uppercase << hex;
  ss << (int)mac_addr->ether_addr_octet[5];
  _mac = ss.str();

  // Launch thread
  _initialized = true;
  thread t1(inject);
  t1.detach();
}

// Inject ARP request to find MAC address
void Injector::injectArp(const string& target) {
  u_int32_t src_ip_addr;
  u_int32_t dst_ip_addr;
  u_int8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  u_int8_t mac_zero_addr[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
  struct libnet_ether_addr *src_mac_addr;

  // Get source IP address
  src_ip_addr = libnet_name2addr4(_handler, (char*)_ip.c_str(),
      LIBNET_DONT_RESOLVE);
  if (src_ip_addr < 0) {
    cerr << "ERROR - Can not determine source ip address for ARP request ";
    cerr << endl << libnet_geterror(_handler) << endl;
    return;
  }

  // Get destination IP address
  dst_ip_addr = libnet_name2addr4(_handler, (char*)target.c_str(),
      LIBNET_DONT_RESOLVE);
  if (dst_ip_addr < 0) {
    cerr << "ERROR - Can not determine target ip address for ARP request ";
    cerr << endl << libnet_geterror(_handler) << endl;
    return;
  }

  // Get source MAC address
  src_mac_addr = libnet_get_hwaddr(_handler);
  if (src_mac_addr == NULL) {
    cerr << "ERROR - Can not determine source mac address for ARP request ";
    cerr << endl << libnet_geterror(_handler) << endl;
    return;
  }

  // Build ARP request header
  _arp_tag = libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4, ARPOP_REQUEST,
      src_mac_addr->ether_addr_octet, (u_int8_t*)(&src_ip_addr), mac_zero_addr,
      (u_int8_t*)(&dst_ip_addr), NULL, 0, _handler, _arp_tag);
  if (_arp_tag == -1) {
    cerr << "ERROR - Can't build ARP header for target ip " << target << endl;
    cerr << libnet_geterror(_handler) << endl;
    return;
  }

  // Build ethernet header
  _eth_arp_tag = libnet_build_ethernet(broadcast, src_mac_addr->ether_addr_octet,
      ETHERTYPE_ARP, NULL, 0, _handler, _eth_arp_tag);
  if (_eth_arp_tag == -1) {
    cerr << "ERROR - Can't build eth header for target ip " << target << endl;
    cerr << libnet_geterror(_handler) << endl;
    return;
  }

  // Writing packet to interface
  if (libnet_write(_handler) == -1) {
    cerr << "ERROR - Can't write packet to interface" << endl;
    cerr << libnet_geterror(_handler) << endl;
  }
}

// Inject ICMP echo request to find reachability
void Injector::injectIcmp(const string& ip, const string& mac) {
  u_int32_t src_ip_addr;
  u_int32_t dst_ip_addr;
  struct libnet_ether_addr *src_mac_addr;
  struct libnet_ether_addr *dst_mac_addr;
  u_int16_t id;
  u_int16_t seq;

  // Generating a random id
  libnet_seed_prand(_handler);
  id = (u_int16_t)libnet_get_prand(LIBNET_PR16);

  // Get source MAC address
  src_mac_addr = libnet_get_hwaddr(_handler);
  if (src_mac_addr == NULL) {
    cerr << "ERROR - Can not determine source mac address for ICMP request";
    cerr << endl << libnet_geterror(_handler) << endl;
    return;
  }

  // Get source IP address
  src_ip_addr = libnet_name2addr4(_handler, (char*)_ip.c_str(),
      LIBNET_DONT_RESOLVE);
  if (src_ip_addr < 0) {
    cerr << "ERROR - Can not determine source ip address for ICMP request";
    cerr << endl << libnet_geterror(_handler) << endl;
    return;
  }

  // Get destination MAC address
  dst_mac_addr = (struct libnet_ether_addr*)ether_aton(mac.c_str());
  if (dst_mac_addr == NULL) {
    cerr << "ERROR - Can not determine target mac address for ICMP request";
    cerr << endl << libnet_geterror(_handler) << endl;
    return;
  }

  // Get destination IP address
  dst_ip_addr = libnet_name2addr4(_handler, (char*)ip.c_str(),
      LIBNET_DONT_RESOLVE);
  if (dst_ip_addr < 0) {
    cerr << "ERROR - Can't determine target ip address for ICMP echo request";
    cerr << endl << libnet_geterror(_handler) << endl;
    return;
  }

  // Build ICMP header
  seq = 1;
  _icmp_tag = libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq, NULL, 0,
      _handler, _icmp_tag);
  if (_icmp_tag == -1) {
    cerr << "ERROR - Can't build icmp echo request for ip " << ip << endl;
    cerr << libnet_geterror(_handler) << endl;
    return;
  }

  // Build IPv4 header
  _ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H, 0, 0, 0,
      127, IPPROTO_ICMP, 0, src_ip_addr, dst_ip_addr, NULL, 0, _handler,
      _ip_tag);
  if (_ip_tag == -1) {
    cerr << "ERROR - Can't build ipv4 header for ip " << ip << endl;
    cerr << libnet_geterror(_handler) << endl;
    return;
  }

  // Build ethernet header
  _eth_ip_tag = libnet_build_ethernet(dst_mac_addr->ether_addr_octet,
      src_mac_addr->ether_addr_octet, ETHERTYPE_IP, NULL, 0, _handler,
      _eth_ip_tag);
  if (_eth_ip_tag == -1) {
    cerr << "ERROR - Can't build eth header for target ip " << ip << endl;
    cerr << libnet_geterror(_handler) << endl;
    return;
  }

  // Writing packet to interface
  if (libnet_write(_handler) == -1) {
    cerr << "ERROR - Can't write packet to interface" << endl;
    cerr << libnet_geterror(_handler) << endl;
  }
}

// Ip address getter
const string& Injector::getIp(void) const {
  return _ip;
}

// Mac address getter
const string& Injector::getMac(void) const {
  return _mac;
}

