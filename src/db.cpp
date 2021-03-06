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
 * @file Implementation of Db class methods
 */

#include "db.h"
using namespace std;

Db* Db::_instance = 0;

// Constructor: does nothing
Db::Db(void) {
  _con = 0;
}

// Destructor: close connection, if any
Db::~Db(void) {
  if (_con != 0) {
    mysql_close(_con);
    _con = 0;
  }
}

// Initialization function
bool Db::init(string host, string user, string pass, string database) {
  // Init MySQL library
  MYSQL *con = mysql_init(NULL);

  // Check library initialization
  if (con == NULL) {
    cerr << "ERROR - Can't connect to MySQL server" << endl;
    return true;
  }

  // Connect to database, using received parameters
  if (mysql_real_connect(con, host.c_str(), user.c_str(), pass.c_str(),
      database.c_str(), 0, NULL, 0) == NULL)
  {
    cerr << "ERROR - " << mysql_error(con) << endl;
    mysql_close(con);
    return true;
  }

  // Check schema is installed, try to install if it's not deployed yet
  _con = con;
  if (installSchema()) {
    cerr << "ERROR - Schema not installed, and can not install" << endl;
    mysql_close(con);
    return true;
  }

  return false;
}

// Performs a query to database
bool Db::query(string sql, Result& result) {
  // Clean resultset
  result.clear();

  // Execute query
  if (mysql_query(_con, sql.c_str())) {
    cerr << "ERROR - Can not execute query" << endl;
    cerr << mysql_error(_con) << endl;
    return true;
  }

  // Extract result after query execution
  MYSQL_RES *res = mysql_store_result(_con);

  // If query did not return any result, no need to process resultset
  if (res == NULL) {
    return false;
  }

  // Extract field info from resultset
  MYSQL_FIELD* fields = mysql_fetch_fields(res);
  int num_fields = mysql_num_fields(res);
  MYSQL_ROW row;

  // Process resultset and store each row on vector
  while ((row = mysql_fetch_row(res))) {
    map<string, string> result_row;
    for (int i = 0; i < num_fields; i++) {
      result_row.insert(pair<string, string>(fields[i].name, row[i]));
    }
    result.push_back(result_row);
  }

  // After processing result, free memory allocated
  mysql_free_result(res);
  return false;
}

// Returns auto-increment value generated by last statement executed
int Db::getLastId(void) const {
  return mysql_insert_id(_con);
}

// Checks if database schemas are installed and install them if needed
// Returns false if no error happened, true either
bool Db::installSchema(void) {
  stringstream sql;
  sql << "SELECT COUNT(*) AS count ";
  sql << "FROM information_schema.tables ";
  sql << "WHERE table_schema = 'swarm' ";
  sql << "AND table_name = 'devices' ";

  // Perform query
  Result result;
  if (query(sql.str(), result)) {
    return true;
  }

  // Check result; if count equals zero, must install schema
  if (not atoi(result.at(0)["count"].c_str())) {
    cout << "Schema not installed, installing ... ";

    sql.str(string());
    sql << "CREATE TABLE devices ( ";
    sql << "id int(11) NOT NULL AUTO_INCREMENT, ";
    sql << "hostname varchar(255) default '', ";
    sql << "mac varchar(17) default '', ";
    sql << "ip varchar(15) default '', ";
    sql << "subnet varchar(15) default '', ";
    sql << "hops int(11) default -1, ";
    sql << "vlan int(11) default -1, ";
    sql << "reachable int(1) default -1, ";
    sql << "PRIMARY KEY (id)) ";

    // Execute schema installation
    if (query(sql.str(), result)) {
      cerr << "ERROR - Can not create database schema" << endl;
      return true;
    }

    cout << "Ok!" << endl;
  }

  return false;
}

