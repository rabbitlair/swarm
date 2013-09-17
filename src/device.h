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
 * @file Class Device definition
 */

#ifndef _DEVICE_H_
#define _DEVICE_H_

  #include <sstream>
  #include <string>

  #include "db.h"
  using namespace std;

  /**
   * Represents a detected network device
   */
  class Device {
    public:
      /**
       * Constructor
       */
      Device(const string& ip = string());

      /**
       * Loads a device from db using its id
       * @param id Identifier of device to load
       * @return True if there was an error, false either
       */
      bool load(const int id);

      /**
       * Inserts or updates device info into database
       * @returns True if there was an error, false either
       */
      bool save(void);

      /**
       * Attribute id getter
       * @return Value of id
       */
      int getId(void) const;

      /**
       * Attribute id setter
       * @param id New value for id
       */
      void setId(const int id);

      /**
       * Attribute hostname getter
       * @return Value of hostname
       */
      const string& getHostname(void) const;

      /**
       * Attribute hostname setter
       * @param hostname New value for hostname
       */
      void setHostname(const string& hostname);

      /**
       * Attribute mac getter
       * @return Value of mac
       */
      const string& getMac(void) const;

      /**
       * Attribute mac setter
       * @param mac New value for mac
       */
      void setMac(const string& mac);

      /**
       * Attribute ip getter
       * @return Value of ip
       */
      const string& getIp(void) const;

      /**
       * Attribute ip setter
       * @param ip New value for ip
       */
      void setIp(const string& ip);

      /**
       * Attribute subnet getter
       * @return Value of subnet
       */
      const string& getSubnetMask(void) const;

      /**
       * Attribute subnet setter
       * @param subnet New value for subnet
       */
      void setSubnetMask(const string& subnet);

      /**
       * Attribute hops getter
       * @return Value of hops
       */
      int getHops(void) const;

      /**
       * Attribute hops setter
       * @param hops New value for hops
       */
      void setHops(const int hops);

      /**
       * Attribute vlan getter
       * @return Value of vlan
       */
      int getVlan(void) const;

      /**
       * Attribute vlan setter
       * @param vlan New value for vlan
       */
      void setVlan(const int vlan);

      /**
       * Attribute reachable getter
       * @return Value of reachable
       */
      int getReachable(void) const;

      /**
       * Attribute reachable setter
       * @param reachable New value for reachable
       */
      void setReachable(const int reachable);

    private:
      int _id;
      string _hostname;
      string _mac;
      string _ip;
      string _subnet;
      int _hops;
      int _vlan;
      int _reachable;
  };

  /**
   * Operator << overload
   * @param os Output data stream where to write device information
   * @param device Object to write to data stream
   * @return Output data stream with device information on it
   */
  ostream& operator << (ostream& os, const Device& device);

#endif

