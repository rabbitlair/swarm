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
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <libconfig.h++>
#include <string>

#include "db.h"
#include "injector.h"
#include "monitor.h"
#include "sniffer.h"

using namespace std;
using namespace libconfig;

// Read all needed options from command line
void readOptions(string& interface, string& filter, string& ip,
    int argc, char **argv);

// Read database settings from config file
void readDbConfig(string file);

/**
 * Main program function
 */
int main(int argc, char **argv) {
  // Check program is running as root, so it can access network interfaces
  if (getuid() && geteuid()) {
    cerr << "ERROR - " << argv[0] << " must be run as root" << endl;
    exit(EXIT_FAILURE);
  }

  // Read db configuration from a plaintext swarm.conf file
  readDbConfig("swarm.conf");

  // Variables needed
  string interface, filter, ip;

  // Read options from command line, also build filter string
  readOptions(interface, filter, ip, argc, argv);

  // Launch sniffer thread
  sniffer->start(interface, filter, ip);

  // Launch injector thread
  injector->start(interface, ip);

  // TODO write end condition
  while (1) {
    sleep(1);
  }

  return EXIT_SUCCESS;
}

// Function which read command line options and reads interface and filters
void readOptions(string& interface, string& filter, string &ip,
    int argc, char **argv)
{
  // Define all accepted options
  const struct option long_options[] {
    {"arp", no_argument, 0, 'a'},
    {"help", no_argument, 0, 'h'},
    {"icmp", no_argument, 0, 'i'},
    {"snmp", no_argument, 0, 's'},
    {"spoof", required_argument, 0, 'S'},
    {"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}
  };

  // Default filter is "ip", for all ip traffic
  filter = "ip";

  // Parse all command line options
  int c;
  while ((c = getopt_long(argc, argv, "ahisSv", long_options, NULL)) != -1) {
    switch (c) {
      case 'a':
        filter.append(" or arp");
        break;

      case 'h':
        cout << "Usage: " << argv[0] << " [options] interface" << endl;
        cout << "Options:" << endl;
        cout << "  -a, --arp         Capture ARP packets" << endl;
        cout << "  -h, --help        Show this help and exit" << endl;
        cout << "  -i, --icmp        Capture ICMP packets" << endl;
        cout << "  -s, --snmp        Capture SNMP packets" << endl;
        cout << "  -v, --version     Show version and exit" << endl;
        cout << endl << "Arguments:" << endl;
        cout << "  -S <ip>, --spoof  Use <ip> as own ip address" << endl;
        exit(EXIT_SUCCESS);

      case 'i':
        filter.append(" or icmp");
        break;

      case 's':
        filter.append(" or snmp");
        break;

      case 'S':
        // Validate ip address in dot separated octets
        struct sockaddr_in sa;
        if (inet_pton(AF_INET, optarg, &(sa.sin_addr)) <= 0) {
          cerr << "Invalid ip address on spoof argument" << endl;
          exit(EXIT_FAILURE);
        }
        ip = optarg;
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

// Reads database configuration from a settings.ini file
void readDbConfig(string file) {
  Config cfg;
  file = "/etc/" + file;

  // Check if settings file exists on /etc. Else, look into /usr/local/etc/
  ifstream f(file.c_str());
  if (not f.good()) {
    file = "/usr/local" + file;
  }
  f.close();

  // Open and parse file: look in /etc and /usr/local/etc
  try {
    cfg.readFile((char*)file.c_str());
  }
  catch(const FileIOException &fioex) {
    cerr << "ERROR - I/O error while reading file" << file << endl;
    exit(EXIT_FAILURE);
  }
  catch(ParseException &pex) {
    cerr << "ERROR - Parse error at " << file << ":" << pex.getLine();
    cerr << " - " << pex.getError() << endl;
    exit(EXIT_FAILURE);
  }

  // Get values from parsed settings file
  try {
    string host = cfg.lookup("host");
    string username = cfg.lookup("username");
    string password = cfg.lookup("password");
    string database = cfg.lookup("database");

    // Init MySQL connection
    if (db->init(host, username, password, database)) {
      exit(EXIT_FAILURE);
    }
  }
  catch(const SettingNotFoundException &nfex) {
    cerr << "Wrong or missing setting name in configuration file" << endl;
  }
}

