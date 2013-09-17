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
 * @file Implementation of Device class methods
 */

#include "device.h"
using namespace std;

// Constructor
Device::Device(const string& ip) {
  _id = 0;
  _hostname = "";
  _mac = "";
  _ip = ip;
  _hops = -1;
  _vlan = -1;
  _reachable = -1;
}

// Loads a device from db using its id
bool Device::load(const int id) {
  stringstream sql;
  Result result;

  // Prepare select query
  sql << "SELECT hostname, mac, ip, subnet, hops, vlan, reachable ";
  sql << "FROM devices WHERE id = " << id;

  // Execute query
  if (db->query(sql.str(), result)) {
    cerr << "ERROR - Can not load a device object by id" << endl;
    return true;
  }

  // If resultset is empty, give a warning
  if (result.empty()) {
    cerr << "ERROR - No device found with id " << id << endl;
    return true;
  }

  // Store values found into object attributes
  _id = id;
  _hostname = result.at(0)["hostname"];
  _mac = result.at(0)["mac"];
  _ip = result.at(0)["ip"];
  _subnet = result.at(0)["subnet"];
  _hops = atoi(result.at(0)["hops"].c_str());
  _vlan = atoi(result.at(0)["vlan"].c_str());
  _reachable = atoi(result.at(0)["reachable"].c_str());

  return false;
}

// Inserts or updates device info into database
bool Device::save(void) {
  stringstream sql;
  Result result;

  // No _id, so must insert a new record
  if (_id == 0) {
    // Prepare sql insert sentence
    sql << "INSERT INTO devices(";
    sql << "hostname, mac, ip, subnet, hops, vlan, reachable) ";
    sql << "VALUES('" << _hostname << "', '" << _mac << "', ";
    sql << "'" << _ip << "', '" << _subnet << "', "<< _hops << ", ";
    sql << _vlan << ", " << _reachable << ") ";

    // Execute insert statement, and check errors
    if (db->query(sql.str(), result)) {
      cerr << "ERROR - Can not insert new device into database" << endl;
      return true;
    }

    // Get id inserted, and save to object attribute
    _id = db->getLastId();
  }
  // Attribute _id has some value, so must update
  else {
    // Prepare update query
    sql << "UPDATE devices SET hostname = '" << _hostname << "', ";
    sql << "mac = '" << _mac << "', ip = '" << _ip << "', subnet = '";
    sql << _subnet << "', hops = " << _hops << ", vlan = " << _vlan << ", ";
    sql << "reachable = " << _reachable << " ";
    sql << "WHERE id = " << _id;

    // Execute statement, and check for errors
    if (db->query(sql.str(), result)) {
      cerr << "ERROR - Can not update device with id " << _id;
      cerr << " into database" << endl;
      return true;
    }
  }
  return false;
}

// Attribute id getter
int Device::getId(void) const {
  return _id;
}

// Attribute id setter
void Device::setId(const int id) {
  _id = id;
}

// Attribute hostname getter
const string& Device::getHostname(void) const{
  return _hostname;
}

// Attribute hostname setter
void Device::setHostname(const string& hostname) {
  _hostname = hostname;
}

// Attribute mac getter
const string& Device::getMac(void) const {
  return _mac;
}

// Attribute mac setter
void Device::setMac(const string& mac) {
  _mac = mac;
}

// Attribute ip getter
const string& Device::getIp(void) const {
  return _ip;
}

// Attribute ip setter
void Device::setIp(const string& ip) {
  _ip = ip;
}

// Attribute subnet getter
const string& Device::getSubnetMask(void) const {
  return _subnet;
}

// Attribute subnet setter
void Device::setSubnetMask(const string& subnet) {
  _subnet = subnet;
}

// Attribute hops getter
int Device::getHops(void) const {
  return _hops;
}

// Attribute hops setter
void Device::setHops(const int hops) {
  _hops = hops;
}

// Attribute vlan getter
int Device::getVlan(void) const {
  return _vlan;
}

// Attribute vlan setter
void Device::setVlan(const int vlan) {
  _vlan = vlan;
}

// Attribute reachable getter
int Device::getReachable(void) const {
  return _reachable;
}

// Attribute reachable setter
void Device::setReachable(const int reachable) {
  _reachable = reachable;
}

// Operator << overload
ostream& operator<<(ostream& os, const Device& device) {
  os << "Ip address:  " << device.getIp() << endl;
  os << "Mac address: " << device.getMac() << endl;
  os << "Reachable:   " << (device.getReachable() == 1 ? "Yes" : "No") << endl;
  return os;
}

