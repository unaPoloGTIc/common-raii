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
 
 string getNonce(int);

/*
  RAII wrapper around GPGME encryption operations.
*/
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

 
};
