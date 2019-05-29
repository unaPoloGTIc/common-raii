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
#ifndef CMMNRAII_H
#define CMMNRAII_H

extern "C" {
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <gpgme.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <syslog.h>
#include <microhttpd.h>
}

#include <array>
#include <string>
#include <memory>
#include <random>
#include <algorithm>

namespace commonRaii { //TODO: add valgrind tests for all raii classes

  using namespace std;
 
#define DEFAULT_USER "nobody"

  /*
    RAII wrapper around PAM's conversation convention.
    Presents *in* to the user and returns the reply that was supplied.
  */
  string converse(pam_handle_t *, string in);
 
  /*
    RAII class to release gpgme keys when leaving scope.
  */
  class keyRaii{
  private:
    gpgme_key_t key;

  public:
    keyRaii();
    ~keyRaii();
    gpgme_key_t &get();  
  };

  /*
    RAII class to release gpgme data when leaving scope.
  */
  class gpgme_data_raii{
  private:
    gpgme_data_t data = nullptr;
    gpgme_error_t err;
  public:
    gpgme_data_raii(const string&);
    gpgme_data_raii();
    gpgme_data_t& get();
    ~gpgme_data_raii();
  };

  /*
    RAII class to release gpgme ctx when leaving scope.
  */
  class gpgme_ctx_raii{
  private:
    gpgme_ctx_t ctx;
    static const gpgme_protocol_t proto{GPGME_PROTOCOL_OpenPGP};
  public:
    gpgme_ctx_raii(string);
    gpgme_ctx_t& get();
    ~gpgme_ctx_raii();
  };

  string getNonce(int);
   
  class encrypter {
  private:
    string plain, gpgHome;
    gpgme_decrypt_flags_t flags = static_cast<gpgme_decrypt_flags_t>(0);

    /*
      RAII helper to encrypt to the public key of *recp*, optionally signing as *sender*
    */
    string encPub(string, bool, bool, string);
  public:
    /*
      RAII wrapper around a gpgme engine
    */
    encrypter(string, string);
    string ciphertext(string, bool, bool, string);
  };

  /*
    RAII class to temporarilly drop privilleges using setegid,seteuid
  */
  class privDropper{
  private:
    uid_t origUid;
    gid_t origGid;
    bool dropped;
    pam_handle_t *pamh;
  public:
    privDropper(pam_handle_t *, struct passwd *);
    ~privDropper();
  }; 
 
  class mhdRespRaii {
  private:
    struct MHD_Response *response;
  public:
    mhdRespRaii(string page);
    ~mhdRespRaii();
    struct MHD_Response *get();
  };
}
#endif //CMMNRAII_H
