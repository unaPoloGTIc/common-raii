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

#define DEFAULT_USER "nobody"


/*
  returns a (hopefully) uniformlly random alphanumeric (lower+uppercase) string of length *len*
*/
  /*
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
  */
/*
  helper to parse a config line into parameters
*/
  /*
class userRecord {
private:
  string trustStr;
public:
  string encryptTo, signStr, webQr, key, pem;
  bool trustFlag, signFlag;
  userRecord(){}
  userRecord(string ss)
  {
    stringstream s{ss};
    s >> encryptTo;
    s >> trustStr;
    s >> signStr;
    if(s)
      s >> webQr;
    if(s)
      s >> key;
    if(s)
      s >> pem;

    trustFlag = (trustStr=="trust"s);
    signFlag = !(signStr=="nosign"s);
  }
  auto get()
  {
    return make_tuple(encryptTo, trustFlag, signStr, signFlag, webQr, key, pem);
  }
};
  */
/*
  helper to parse a config file
*/
  /*
class userDb {
private:
  userRecord rec;
  bool hasKey{false};
public:
  userDb(string p)
  {
    fstream f{p+"/.auth_gpg"};
    if (!f)
      return;

    string l;
    while (getline(f, l))
      {
	if (l.length() == 0 || l[0]=='#')
	  continue;
	userRecord r{l};
	rec = r;
	hasKey = true;
	break;
      }
  }

  bool has()
  {
    return hasKey;
  }

  auto get()
  {
    return rec.get();
  }
};
  */
/*
  RAII class to temporarilly drop privilleges using setegid,seteuid
*/
  /*
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
  */
  //string globalChallenge{};

/*
  wrapper around libcppgenqr to get a qr representation of a string
*/
  /*
string getQR()
{
  const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(globalChallenge.c_str(), qrcodegen::QrCode::Ecc::QUARTILE);//TODO: in order to use HIGH, split the challenge into 10556 bits pieces or risk 'qrcodegen::data_too_long' exception
  return qr.toSvgString(1);
}
  */
//globals, carefull.
//string globalUser, globalPass;
//bool globalAuth;

//RAII class to hold a MHD_response
   /*
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
   */
/*
  called by libmicrohttpd
  serve a QR image over http/s and optionally authenticate the requester.
*/
  /*
static int
answer_to_connection (void *cls, struct MHD_Connection *connection,
		      const char *url, const char *method,
		      const char *version, const char *upload_data,
		      size_t *upload_data_size, void **con_cls)
{
  int fail;
  int ret;

  if (0 != strncmp (method, "GET", 4))
    return MHD_NO;
  if (NULL == *con_cls)
    {
      *con_cls = connection;
      return MHD_YES;
    }

  char *user;
  char *pass;
  pass = NULL;

  user = MHD_basic_auth_get_username_password (connection, &pass);

  unique_ptr<char[]> userRaii(user);
  unique_ptr<char[]> passRaii(pass);

  if ( globalAuth && (!userRaii || !passRaii ||
		      string{userRaii.get()} != globalUser ||
		      string{passRaii.get()} != globalPass ))
    {
      const char *page = "<html><body>Invalid credentials</body></html>";
      auto response{mhdRespRaii(page)};
      ret = MHD_queue_basic_auth_fail_response (connection,
						"QR login",
						response.get());
      return ret;
    }

  auto qr{getQR()};
  string strayXml{R"(<?xml version="1.0" encoding="UTF-8"?>)"};
  string strayDoc{R"(<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">)"};
  qr.replace(qr.find(strayXml), strayXml.length(),""s);
  qr.replace(qr.find(strayDoc), strayDoc.length(),""s);
  auto content = "<!DOCTYPE html><html><head>"s+
    R"(<style>
     figure {
         max-width: 17cm;
     }
     </style>)" +
    "<title>QR challenge</title></head><body><figure>"s +
    qr +
    "</figure></body></html>"s;
  auto response{mhdRespRaii(content)};
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response.get());
  return ret;
}
  */
/*
  helper to make sense of the QR parameter in the config
*/
   /*
auto handleAuthTlsParams(string webQr)
{
  bool webQrFlag{(webQr=="webQrAuthTls")||//TODO: refactor strings
		 (webQr=="webQrNoAuthTls")||
		 (webQr=="webQrAuthNoTls")||
		 (webQr=="webQrNoAuthNoTls")};
  globalAuth = (webQrFlag &&
		!(webQr=="webQrNoAuthNoTls" || webQr=="webQrNoAuthTls"));
  bool tlsFlag = {webQrFlag &&
		  !(webQr=="webQrNoAuthNoTls" || webQr=="webQrAuthNoTls")};

  return make_tuple(webQrFlag, tlsFlag);
}
   */
/*
  RAII class to hold a webserver to serve QR codes
*/
    /*
class webServerRaii {
private:
  struct MHD_Daemon * d{nullptr};
  static constexpr int fileSize{2'000};
  char key_pem[fileSize]{""};
  char cert_pem[fileSize]{""};
  bool tlsFlag;
public:
  webServerRaii(bool _tlsFlag = true, string key = ""s, string cert = ""s):tlsFlag{_tlsFlag} {
    //if needed, use TLS
    if (tlsFlag)
      {
	ifstream keyRead{key};
	if (!keyRead)
	  throw(runtime_error{"Can't open key file"s});
	keyRead.get(key_pem, fileSize-1,'\0');
	ifstream certRead{cert};
	if (!certRead)
	  throw(runtime_error{"Can't open cert file"s});
	certRead.get(cert_pem, fileSize-1,'\0');
      }
  }

  //start serving QR, return a string description to display to the user
  //  should have been called by ctor, but couldn't due to scoping issues in pam_auth
  string start()
  {
    string clearMsg{};
    int useTls{tlsFlag?MHD_USE_TLS:0};
    d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | useTls,
			 0,
			 nullptr,
			 nullptr,
			 &answer_to_connection,
			 nullptr,
			 MHD_OPTION_HTTPS_MEM_KEY, key_pem,
			 MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
			 MHD_OPTION_END);
    if (!d)
      {
	clearMsg = "\nFailed starting server for QR "s + clearMsg;
      } else {
      stringstream ss{};
      auto dinfo{MHD_get_daemon_info(d, MHD_DAEMON_INFO_BIND_PORT)};
      ss<<"\nFor QR point your browser at http"s << (tlsFlag?"s"s:""s) << "://<this-host>:"s<<dinfo->port;
      if (globalAuth)
	ss<<"\nAuthenticate as '" << globalUser << "' and '"s<<globalPass<<"'";
      clearMsg = ss.str() + clearMsg;
    }
    return clearMsg;
  }

  ~webServerRaii() {
    if (d)
      {
	MHD_stop_daemon(d);
      }
  }
};
    */
}
