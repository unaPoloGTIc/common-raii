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

namespace commonRaii {

using namespace std;
 
#define DEFAULT_USER "nobody"

/*
  RAII wrapper around PAM's conversation convention.
  Presents *in* to the user and returns the reply that was supplied.
*/
template<typename resp>
resp converse(pam_handle_t *pamh, string in)
{
  const void *vconv{nullptr};
  if (pam_get_item(pamh, PAM_CONV, &vconv) == PAM_SUCCESS)
    {
      const struct pam_conv *conv{static_cast<decltype(conv)>(vconv)};
      try
	{
	  if (vconv != nullptr && conv != nullptr && conv->conv != nullptr)
	    {
	      pam_message m{PAM_PROMPT_ECHO_ON, in.c_str() };
	      pam_response *rr{nullptr};
	      array<const struct pam_message*, 1> marr{&m};

	      if (conv->conv(marr.size(), marr.data(), &rr, conv->appdata_ptr) != PAM_SUCCESS)
		throw runtime_error("App callback failed"s);

	      if (rr != nullptr && rr->resp != nullptr)
		{
		  unique_ptr<char[]> uniqResp(rr->resp);
		  string stealResp{uniqResp.get()};
		  return resp{stealResp};
		}
	      throw runtime_error("Empty response"s);
	    }
	}
      catch(...)
	{
	  throw;
	}
    }
  throw runtime_error("pam_get_item() failed"s);
}
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
    RAII helper to encrypt ro the public key of *recp*, optionally signing as *sender*
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
  privDropper(pam_handle_t *pam, struct passwd *p):pamh{pam},origUid{geteuid()}, origGid{getegid()}, dropped{false}
  {
    if (origUid == 0)
      {
	if (setegid(p->pw_gid) != 0)
	  throw runtime_error{"setegid() failed"s};
	if (seteuid(p->pw_uid) != 0)
	  {
	    setegid(origGid);//Should be RAII but it's probably useless if we got here
	    throw runtime_error{"seteuid() failed"s};
	  }
	dropped = true;
      }

  }
  ~privDropper()
  {
    if (dropped)
      {
	if (seteuid(origUid) != 0 || setegid(origGid) != 0)
	  {
	    pam_syslog(pamh, LOG_WARNING, "failed regaining privs, remaining pam modules in the stack might misbehave");
	  }
      }
  }
}; 
 
 class mhdRespRaii {
private:
  struct MHD_Response *response;
public:
  mhdRespRaii(string page)
  {
    response = MHD_create_response_from_buffer (page.length(),
						(void *)(page.c_str()),
						MHD_RESPMEM_MUST_COPY);
  }
  ~mhdRespRaii()
  {
    if (response)
      MHD_destroy_response (response);
  }
  auto get()
  {
    return response;
  }
};
}
#endif //CMMNRAII_H
