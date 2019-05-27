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

  gpgme_key_t &keyRaii::get()
  {
    return key;
  }

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
  
  gpgme_data_raii::gpgme_data_raii(const string& str)
  {
    if (auto err{gpgme_data_new_from_mem(&data,str.c_str(), str.length(), 1)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't init gpgme data from mem "s + string{gpgme_strerror(err)});
  }
  gpgme_data_raii::gpgme_data_raii()
  {
    if (auto err{gpgme_data_new(&data)}; err != GPG_ERR_NO_ERROR)
      throw runtime_error("Can't init gpgme empty data "s + string{gpgme_strerror(err)});
  }

  gpgme_data_t& gpgme_data_raii::get()
  {
    return data;
  }

  gpgme_data_raii::~gpgme_data_raii(){
    if(data)
      gpgme_data_release (data);
  }

  gpgme_ctx_raii::gpgme_ctx_raii(string gpgHome)
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

  gpgme_ctx_t& gpgme_ctx_raii::get()
  {
    return ctx;
  }

  gpgme_ctx_raii::~gpgme_ctx_raii()
  {
    if(ctx)
      gpgme_release(ctx);
  }
  
  encrypter::encrypter(string s, string gpghome):plain{s},gpgHome{gpghome}{}

  string encrypter::ciphertext(string recp, bool trust = false, bool sign = true, string sender = "")
  {
    return encPub(recp, trust, sign, sender);
  }

  string  encrypter::encPub(string recp, bool trust = false, bool sign = true, string sender = ""s)
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
}
