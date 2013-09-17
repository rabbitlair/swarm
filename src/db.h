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
 * @file Class Db definition (mysql support only). Singleton pattern.
 */

#ifndef _DB_H_
#define _DB_H_

  #include <algorithm>
  #include <iostream>
  #include <map>
  #include <mysql/mysql.h>
  #include <sstream>
  #include <string>
  #include <vector>
  using namespace std;

  // Define row and resultset types
  typedef map<string,string> Row;
  typedef vector<Row> Result;

  // TODO Implement support for sqlite, postgresql and mongodb

  /**
   * Singleton class which implements database connection
   */
  class Db {
    public:

      /**
       * Implementation of Singleton pattern
       * @return Pointer to singleton database object
       */
      static Db* getInstance(void) {
        if (_instance == 0) {
          _instance = new Db();
        }
        return _instance;
      }

      /**
       * Destroyer for singleton database object
       */
      static void destroy(void) {
        delete _instance;
      }

      /**
       * Creates dabatase connection using parameters
       * @param host Network address of database server
       * @param user Name of user to connect to db server
       * @param pass Password of database user
       * @param database Name of database to use
       * @return True if connection was not successful, false either
       */
      bool init(string host, string user, string pass, string database);

      /**
       * Executes a query onto the database and returns the result as a vector
       * @param sql SQL sentence to execute
       * @param result Vector of assciative maps, each one storing a result row
       * @return True if query was not executed, false either
       */
      bool query(string sql, Result& result);

      /**
       * Returns the value for an auto-increment column by previous statement
       * @returns Value of last inserted or updated auto-increment id
       */
       int getLastId(void) const;

    protected:
      // Constructor, destructor, copy constructor and assing operator
      // are protected due to singleton pattern implementation
      Db(void);
      ~Db(void);
      Db(const Db& db);
      Db& operator=(const Db& db);

    private:
      // Private function which installs database schema
      bool installSchema(void);

      // Attributes
      static Db* _instance;
      MYSQL *_con;
  };

  #define db Db::getInstance()

#endif

