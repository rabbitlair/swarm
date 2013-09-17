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
 * @file Class definition for mutex monitor. Singleton pattern.
 */

#ifndef _MONITOR_H_
#define _MONITOR_H_

  #include <map>
  #include <mutex>
  #include <stdexcept>
  #include <string>

  #include "device.h"
  using namespace std;

  // Type definitions
  typedef map<string,Device> Devices;

  /**
   * List of network devices found. Implements Singleton pattern, and all
   * access to internal data structure are mutex protected by own lock
   */
  class Monitor {
    public:

      /**
       * Implementation of Singleton pattern
       * @return Pointer to singleton monitor object
       */
      static Monitor* getInstance(void) {
        if (_instance == 0) {
          _instance = new Monitor();
        }
        return _instance;
      }

      /**
       * Destroyer for singleton monitor object
       */
      static void destroy(void) {
        delete _instance;
      }

      /**
       * Adds a new device to monitor
       * @param device Device object to add to monitor
       * @return True if new device was inserted, false, either
       */
      bool addDevice(Device& device);

      /**
       * Updates an stored device, identified by its ip address
       * @param ip Ip address which identifies device to update
       * @param device Device object to store in place of existing one
       * @return True if there was an error, false either
       */
      bool updateDevice(const string& ip, Device& device);

      /**
       * Returns a concrete device identified by its ip address
       * @param ip Ip address of the device to search for
       * @throws Standard exception if device was not found
       * @return Device which ip address is the received one
       */
      Device getDevice(const string& ip) throw (exception);

      /**
       * Checks if some ip address has been registered before
       * @param ip Ip address to check if has been registered on monitor
       * @return True if ip address was found, false either
       */
      bool checkDevice(const string& ip);

      /**
       * Reset internal pointer to first device object
       */
      void reset(void);

      /**
       * Advance internal pointer to next device object
       */
      void next(void);

      /**
       * Get const reference to device object pointed by internal pointer
       * @return Const reference to device object stored on monitor
       */
       const Device& getCurrent(void) const;

      /**
       * Returns number of devices registered
       * @return Integer which indicates the number of devices
       */
      int count(void) const;

    protected:
      // Constructor, destructor, copy constructor and assing operator
      // are protected due to singleton pattern implementation
      Monitor(void);
      ~Monitor(void);
      Monitor(const Monitor& monitor);
      Monitor& operator=(const Monitor& monitor);

    private:
      Devices _devices;
      Devices::const_iterator _it;
      mutex _mutex;
      static Monitor* _instance;
  };

  #define monitor Monitor::getInstance()

#endif

