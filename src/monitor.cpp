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
 * @file Implementation of class Monitor methods
 */

#include "monitor.h"
using namespace std;

Monitor* Monitor::_instance = 0;

// Constructor: does nothing
Monitor::Monitor(void) {
}

// Adds new device to monitor
bool Monitor::addDevice(Device& device) {
  // Map insert operation returns a pair of iterator and boolean
  pair<Devices::iterator, bool> result;

  // Protect access using mutex lock
  _mutex.lock();
  result = _devices.insert(pair<string,Device>(device.getIp(), device));
  _mutex.unlock();

  // Save updated device to database
  result.first->second.save();

  // Return true if device was inserted, false if it existed
  return result.second;
}

// Updates a device, searching by ip address
bool Monitor::updateDevice(const string& ip, Device& device) {
  // Check if received ip is registered, else exit
  if (not checkDevice(ip)) {
    return true;
  }

  // Actually update stored device
  _mutex.lock();
  _devices[ip] = device;
  _mutex.unlock();

  // Save updated device to database
  _devices[ip].save();

  return false;
}

// Return reference to concrete device identified by ip address
Device Monitor::getDevice(const string& ip) throw (exception) {
  // Map find operation returns an iterator
  Devices::iterator it;

  // Search selected device, using mutex lock
  _mutex.lock();
  it = _devices.find(ip);
  _mutex.unlock();

  // Throw exception if device not found
  if (it == _devices.end()) {
    throw exception();
  }

  // Return device if found
  _mutex.lock();
  Device device = it->second;
  _mutex.unlock();
  return device;
}

// Checks if some ip address has been registered before
bool Monitor::checkDevice(const string& ip) {
  _mutex.lock();
  bool found = (_devices.find(ip) != _devices.end());
  _mutex.unlock();

  return found;
}

// Reset internal pointer to first device object
void Monitor::reset(void) {
  _mutex.lock();
  _it = _devices.begin();
  _mutex.unlock();
}

// Advance internal pointer to next device object
void Monitor::next(void) {
  _mutex.lock();
  ++_it;
  _mutex.unlock();

  // It new position is end, reset pointer
  if (_it == _devices.end()) {
    reset();
  }
}

// Get const reference to device object pointed by internal pointer
const Device& Monitor::getCurrent(void) const {
  return _it->second;
}

// Returns number of devices stored
int Monitor::count(void) const {
  return _devices.size();
}

