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
 * @file Capture functions declaration
 */

#ifndef _CAPTURE_H_
#define _CAPTURE_H_

  #include <arpa/inet.h>
  #include <iostream>
  #include <netinet/ether.h>
  #include <netinet/ip.h>
  #include <pcap.h>
  #include <string>

  #include "injector.h"
  #include "sniffer.h"

  // TODO Implement SNMP processing, to extract hostname. Maybe getnameinfo?
  // TODO Implement traceroute to guess device distance in network hops

  /**
   * Callback to give response to a captured packet by libpcap
   * @param args Custom arguments to pass to function
   * @param header Header of captured data, in libpcap format
   * @param packet Captured packet
   */
  void gotPacket(u_char *args, const struct pcap_pkthdr *header,
      const u_char *packet);

  /**
   * Inits libpcap live capture. Launch as thread.
   */
  void capture(void);

  /**
   * Injects packets into wire, using libnet capabilities. Launch as thread.
   */
  void inject(void);

#endif

