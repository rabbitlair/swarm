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
 * @file Class Injector definition. Singleton pattern implementation
 */

#ifndef _INJECTOR_H_
#define _INJECTOR_H_

  #include <iomanip>
  #include <iostream>
  #include <libnet.h>
  #include <netinet/ether.h>
  #include <string>
  #include <thread>

  #include "actions.h"
  #include "monitor.h"
  using namespace std;

  /**
   * Singleton object which reads devices from monitor, and injects packets
   * to some interface to try to guess device information. Uses libnet.
   */
  class Injector {
    public:

      /**
       * Implementation of Singleton pattern
       * @return Pointer to singleton injector object
       */
      static Injector* getInstance(void) {
        if (_instance == 0) {
          _instance = new Injector();
        }
        return _instance;
      }

      /**
       * Destroyer for singleton injector object
       */
      static void destroy(void) {
        delete _instance;
      }

      /**
       * Initialize injector object, and launch as thread
       * @param iface Name of network interface on which inject packets
       * @param ip Optional ip address to perform ip spoofing
       */
      void start(string& iface, string ip = "");

      /**
       * Inject ARP request to find MAC address
       * @param target Ip address of device whose mac address we want to guess
       */
      void injectArpRequest(const string& target);

      /**
       * Inject ARP response to perform IP spoofing
       * @param ip Ip address of target which ARP table will be poisoned
       * @param mac Mac address of target which ARP table will be poisoned
       */
      void injectArpSpoofResponse(const string& ip, const string& mac);

      /**
       * Inject ICMP echo request to find reachability
       * @param ip Ip address of device whose reachability we want to guess
       * @param mac Mac address of device whose reachability we want to guess
       */
      void injectIcmp(const string& ip, const string& mac);

      /**
       * Spoofed ip address getter
       * @return Spoofed ip address for inject interface
       */
      const string& getSpoofIp(void) const;

      /**
       * Own ip address getter
       * @return Ip address of interface on which we are injecting packets
       */
      const string& getIp(void) const;

      /**
       * Own mac address getter
       * @return Mac address of interface on which we are injecting packets
       */
      const string& getMac(void) const;

    protected:
      // Constructor, destructor, copy constructor and assing operator
      // are protected due to singleton pattern implementation
      Injector(void);
      ~Injector(void);
      Injector(const Injector& injector);
      Injector& operator=(const Injector& injector);

    private:
      string _spoof_ip;
      string _ip;
      string _mac;
      libnet_ptag_t _eth_arp_tag;
      libnet_ptag_t _arp_tag;
      libnet_ptag_t _eth_ip_tag;
      libnet_ptag_t _ip_tag;
      libnet_ptag_t _icmp_tag;
      libnet_t* _handler;
      bool _initialized;
      static Injector* _instance;
  };

  #define injector Injector::getInstance()

#endif

