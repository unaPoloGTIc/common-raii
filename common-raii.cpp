/*
  Copyright 2019 Sharon Dvir

  Unless authorized beforehand and in writting by the author,
  this program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "common-raii.h"


namespace commonRaii {

using namespace std;

  //#define DEFAULT_USER "nobody"

  keyRaii::keyRaii():key{nullptr}{}
  keyRaii::~keyRaii()
  {
    if (key)
      gpgme_key_release (key);
  }

  keyRaii::gpgme_key_t &get()
  {
    return key;
  }
  
}
