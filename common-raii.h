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

#include <iostream>
#include <fstream>
#include <array>
#include <string>
#include <sstream>
#include <memory>
#include <random>
#include <algorithm>
#include <chrono>
#include <map>
#include <future>
#include <qrcodegen/QrCode.hpp>
#include <boost/algorithm/string.hpp>

namespace commonRaii {

using namespace std;
  
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
  keyRaii():key{nullptr}{}
  ~keyRaii()
  {
    if (key)
      gpgme_key_release (key);
  }

  gpgme_key_t &get()
  {
    return key;
  }
  
};

/*
  RAII class to release gpgme data when leaving scope.
*/
class gpgme_data_raii{
private:
  gpgme_data_t data = nullptr;
  gpgme_error_t err;
public:
  gpgme_data_raii(const string& str)
  {
    if (auto err{gpgme_data_new_from_mem(&data,str.c_str(), str.length(), 1)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't init gpgme data from mem "s + string{gpgme_strerror(err)});
  }
  gpgme_data_raii()
  {
    if (auto err{gpgme_data_new(&data)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't init gpgme empty data "s + string{gpgme_strerror(err)});
  }

  gpgme_data_t& get()
  {
    return data;
  }

  ~gpgme_data_raii(){
    if(data)
      gpgme_data_release (data);
  }
};

/*
  RAII class to release gpgme ctx when leaving scope.
*/
class gpgme_ctx_raii{
private:
  gpgme_ctx_t ctx;
  static const gpgme_protocol_t proto{GPGME_PROTOCOL_OpenPGP};
public:
  gpgme_ctx_raii(string gpgHome)
  {
    gpgme_check_version (NULL);
    if (auto err{gpgme_engine_check_version(proto)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't init libgpgme "s + string{gpgme_strerror(err)});

    if (auto err{gpgme_new(&ctx)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't create libgpgme context "s + string{gpgme_strerror(err)});
    if (auto err{gpgme_ctx_set_engine_info(ctx, proto, NULL, gpgHome.c_str())}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't set libgpgme engine info "s +  string{gpgme_strerror(err)});
    if (auto err{gpgme_set_protocol(ctx, proto)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't set libgpgme protocol "s + string{gpgme_strerror(err)});

    gpgme_set_armor (ctx, 1);
  }

  gpgme_ctx_t& get()
  {
    return ctx;
  }

  ~gpgme_ctx_raii()
  {
    if(ctx)
      gpgme_release(ctx);
  }
};

 
 string getNonce(int);


/*
  Helper class to get challenges.
*/
 /*
class challengeHandler {
private:
  
  string nonce(int len = 10)
  {
    return getNonce(len);
  }

public:
  challengeHandler(){}

  pair<string, string> getChallenge(string gpgHome, string recp, bool trust=false, bool sign=true, string sender="")
  {
    auto pass{nonce()};
    auto plaintext{pass};
    encrypter enc{plaintext, gpgHome};
    return {enc.ciphertext(recp, trust, sign, sender),pass};
  }
};
 */
 
};
