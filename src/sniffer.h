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
 * @file Sniffer class declaration. Singleton pattern implementation
 */

#ifndef _SNIFFER_H_
#define _SNIFFER_H_

  #include <cstring>
  #include <ifaddrs.h>
  #include <iomanip>
  #include <iostream>
  #include <netinet/ether.h>
  #include <netinet/ip_icmp.h>
  #include <pcap.h>
  #include <string>
  #include <thread>
  #include <set>

  #include "actions.h"
  #include "monitor.h"
  using namespace std;

  /**
   * Singleton object which captures network packets from some interface,
   * using libpcap, reads some information about them, and then stores the
   * network devices information on monitor registry.
   */
  class Sniffer {
    public:

      /**
       * Implementation of Singleton pattern
       * @return Pointer to singleton sniffer object
       */
      static Sniffer* getInstance(void) {
        if (_instance == 0) {
          _instance = new Sniffer();
        }
        return _instance;
      }

      /**
       * Destroyer for singleton sniffer object
       */
      static void destroy(void) {
        delete _instance;
      }

      /**
       * Initialize sniffer and launch it as thread
       * @param iface Name of network interface on which we want to sniff
       * @param filter_str Filter, on libpcap format, to apply on capture
       * @param spoof Custom ip address to use as own (spoofing)
       */
      void start(string& iface, string& filter_str, string spoof = "");

      /**
       * Process sniffed ARP packet. Extract some device's mac address
       * @param packet Captured packet from network interface
       */
      void processArp(const u_char* packet);

      /**
       * Process sniffed VLAN tagged packet. Extract some device's vlan
       * @param packet Captured packet from network interface
       */
      void processVlan(const u_char* packet);

      /**
       * Process sniffed ICMP tagged packet. Extract some device's reachability
       * @param packet Captured packet from network interface
       * @param src Data packet's source ip address, to avoid double processing
       */
      void processIcmp(const u_char* packet, const string& src);

      /**
       * Getter for libpcap capture session handler
       * @return Handler of libpcap capture session
       */
      pcap_t* getHandler(void) const;

      /**
       * Own ip address getter
       * @return Ip address of interface on which we are hearing
       */
      const string& getIp(void) const;

      /**
       * Spoofed ip address getter
       * @return Spoofed ip address for capture interface
       */
      const string& getSpoofIp(void) const;

      /**
       * Checks if some arbitrary valid ip address is private. Based on IANA
       * reserved private network ranges.
       * @param ip Ip address, on dot separated decimals format
       * @return True if ip is private, false if it's public
       */
      bool ipIsPrivate(const string& ip) const;

    protected:
      // Constructor, destructor, copy constructor and assing operator
      // are protected due to singleton pattern implementation
      Sniffer(void);
      ~Sniffer(void);
      Sniffer(const Sniffer& sniffer);
      Sniffer& operator=(const Sniffer& sniffer);

    private:
      // Private function which guess some iface ip address
      string getOwnIp(const string& name) const;

      // Attributes
      string _errbuf;
      string _ip;
      string _spoof_ip;
      pcap_t* _handler;
      bool _initialized;
      static Sniffer* _instance;

      // Internal list of attributes already sniffed. Avoid repeating tasks
      set<string> _macs_processed;
      set<string> _reachability_processed;
  };

  #define sniffer Sniffer::getInstance()

#endif

