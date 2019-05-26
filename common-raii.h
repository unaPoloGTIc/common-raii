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
//#include <chrono>
//#include <map>
#include <future>
//#include <qrcodegen/QrCode.hpp>
//#include <boost/algorithm/string.hpp>

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

 string getNonce(int len = 10)
{
  static string chars{"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"s};
  auto ret{""s};
  random_device rd{};
  mt19937 g{rd()};
  uniform_int_distribution<> d(0, chars.size()-1);
  
  shuffle(chars.begin(), chars.end(), g);
  
  for (int i=0; i < len; i++)
    ret.push_back(chars[d(g)]);
  return ret;
}


class encrypter {
private:
  string plain, gpgHome;
  gpgme_decrypt_flags_t flags = static_cast<gpgme_decrypt_flags_t>(0);

  /*
    RAII helper to encrypt ro the public key of *recp*, optionally signing as *sender*
  */

  string encPub(string recp, bool trust = false, bool sign = true, string sender = ""s)
  {
    gpgme_ctx_raii ctx(gpgHome);
    gpgme_data_raii in{plain};
    gpgme_data_raii out{};

    string recpFormatted{"--\n "s + recp + " \n"s};
    gpgme_encrypt_flags_t params{trust?GPGME_ENCRYPT_ALWAYS_TRUST:static_cast<gpgme_encrypt_flags_t>(0)};
    if (sign)
      {
	if (auto err{gpgme_op_keylist_start (ctx.get(), sender.c_str(), 0)}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("gpgme_op_keylist_start() failed"s + string{gpgme_strerror(err)});
	keyRaii key;
	if (auto err{gpgme_op_keylist_next (ctx.get(), &key.get())}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("gpgme_op_keylist_next() failed "s + string{gpgme_strerror(err)});
	if (auto err{gpgme_op_keylist_end(ctx.get())}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("gpgme_op_keylist_end() failed "s + string{gpgme_strerror(err)});
	if (auto err{gpgme_signers_add (ctx.get(), key.get())}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("Can't add signer "s + sender + " " + string{gpgme_strerror(err)});
	if (auto err{gpgme_op_encrypt_sign_ext(ctx.get(),
					       NULL,
					       recpFormatted.c_str(),
					       params,
					       in.get(),
					       out.get())}; err != GPG_ERR_NO_ERROR)
	  {
	    throw runtime_error("Can't encrypt/sign with keys "s + recp + ", " + sender + " : " + string{gpgme_strerror(err)});
	  }
      }
    else
      {
	if (auto err{gpgme_op_encrypt_ext(ctx.get(),
					  NULL,
					  recpFormatted.c_str(),
					  params,
					  in.get(),
					  out.get())}; err != GPG_ERR_NO_ERROR)
	  throw runtime_error("Can't encrypt to "s + recp + " "s +  string{gpgme_strerror(err)});
      }

    constexpr int buffsize{500};
    char buf[buffsize + 1] = "";
    int ret = gpgme_data_seek (out.get(), 0, SEEK_SET);
    string s{};
    while ((ret = gpgme_data_read (out.get(), buf, buffsize)) > 0)
      {
	buf[ret] = '\0';
	s += string{buf};
      }
    return s;
  }

public:

  /*
    RAII wrapper around a gpgme engine
  */

  encrypter(string s, string gpghome):plain{s},gpgHome{gpghome}
  {}

  string ciphertext(string recp, bool trust = false, bool sign = true, string sender = "")
  {
    return encPub(recp, trust, sign, sender);
  }
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
