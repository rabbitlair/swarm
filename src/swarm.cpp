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
 * @file Main function of Swarm Net
 */

#include "config.h"
#include <getopt.h>
#include <iostream>
#include <string>

#include "db.h"
#include "injector.h"
#include "monitor.h"
#include "sniffer.h"

using namespace std;

/**
 * Read all needed options from command line
 */
void readOptions(string& interface, string& filter, int argc, char **argv);

/**
 * Main program function
 */
int main(int argc, char **argv) {
  // Check program is running as root, so it can access network interfaces
  if (getuid() && geteuid()) {
    cerr << "ERROR - " << argv[0] << " must be run as root" << endl;
    exit(EXIT_FAILURE);
  }

  // TODO Read db configuration from a plaintext settings file

  // Init MySQL connection
  if (db->init("localhost", "swarm", "swarm", "swarm")) {
    exit(EXIT_FAILURE);
  }

  // Variables needed
  string interface, filter;

  // Read options from command line, also build filter string
  readOptions(interface, filter, argc, argv);

  // Launch sniffer thread
  sniffer->start(interface, filter);

  // Launch injector thread
  injector->start(interface);

  // TODO write end condition
  while (1) {
    sleep(1);
  }

  return EXIT_SUCCESS;
}

// Function which read command line options and reads interface and filters
void readOptions(string& interface, string& filter, int argc, char **argv) {
  // Define all accepted options
  const struct option long_options[] {
    {"arp", no_argument, 0, 'a'},
    {"help", no_argument, 0, 'h'},
    {"icmp", no_argument, 0, 'i'},
    {"snmp", no_argument, 0, 's'},
    {"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
  };

  // Default filter is "ip", for all ip traffic
  filter = "ip";

  // Parse all command line options
  int c;
  while ((c = getopt_long(argc, argv, "ahisv", long_options, NULL)) != -1) {
    switch (c) {
      case 'a':
        filter.append(" or arp");
        break;

      case 'h':
        cout << "Usage: " << argv[0] << " [options] interface" << endl;
        cout << "Options:" << endl;
        cout << "  -a, --arp       Capture ARP packets" << endl;
        cout << "  -h, --help      Show this help and exit" << endl;
        cout << "  -i, --icmp      Capture ICMP packets" << endl;
        cout << "  -s, --snmp      Capture SNMP packets" << endl;
        cout << "  -v, --version   Show version and exit" << endl;
        exit(EXIT_SUCCESS);

      case 'i':
        filter.append(" or icmp");
        break;

      case 's':
        filter.append(" or snmp");
        break;

      case 'v':
        cout << argv[0] << " - version " << VERSION << endl;
        exit(EXIT_SUCCESS);

      default:
        cerr << "Usage: " << argv[0] << " [options] interface" << endl;
        exit(EXIT_FAILURE);
    }
  }

  // Check mandatory unique argument (interface)
  if (argc - optind != 1) {
    cerr << "Usage: " << argv[0] << " [options] interface" << endl;
    exit(EXIT_FAILURE);
  }
  else {
    interface = argv[optind++];
  }
}

