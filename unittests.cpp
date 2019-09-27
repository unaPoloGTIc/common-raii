#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include <curl/curl.h>
#include <gpgme.h>
#include <security/pam_appl.h>
}
#include "common-raii.h"

using namespace std;
using namespace commonRaii;

string validEmail{"vendor@mmodt.com"s};
string invalidEmail{"some@sender.com"s};

TEST(unitTests, gpgme_ctx_create) {
  ASSERT_NO_THROW(gpgme_ctx_raii c{"~/.gnupg/"s};);
}

TEST(unitTests, gpgme_ctx_operate) {
  gpgme_ctx_raii c{"~/.gnupg/"s};
  ASSERT_EQ(gpgme_op_keylist_start(c.get(), invalidEmail.c_str(), 0),
            GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_op_keylist_end(c.get()), GPG_ERR_NO_ERROR);
}

TEST(unitTests, keyRaii_create) { ASSERT_NO_THROW(keyRaii k{};); }

TEST(unitTests, gpgme_data_create_empty) {
  ASSERT_NO_THROW(gpgme_data_raii d{};);
}

TEST(unitTests, gpgme_data_create_string) {
  ASSERT_NO_THROW(gpgme_data_raii d{"some data to be copied"s};);
}

class Unit : public ::testing::Test {
protected:
  gpgme_ctx_raii c{"~/.gnupg/"s};

public:
  Unit() {}
  ~Unit() {}
};

TEST_F(Unit, keyRaii_operate) {
  keyRaii k{};
  ASSERT_EQ(gpgme_op_keylist_start(c.get(), validEmail.c_str(), 0),
            GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_op_keylist_next(c.get(), &k.get()), GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_op_keylist_end(c.get()), GPG_ERR_NO_ERROR);
  ASSERT_EQ(gpgme_signers_add(c.get(), k.get()), GPG_ERR_NO_ERROR);
}

TEST_F(Unit, gpgme_data_operate) {
  auto str{"some data to be encrypted"s};
  gpgme_data_raii in{str};
  gpgme_data_raii out{};

  ASSERT_EQ(gpgme_op_encrypt_ext(
                c.get(), NULL, string{"--\n "s + validEmail + " \n"s}.c_str(),
                GPGME_ENCRYPT_ALWAYS_TRUST, in.get(), out.get()),
            GPG_ERR_NO_ERROR);
  constexpr int buffsize{500};
  char buf[buffsize + 1] = "";
  int ret = gpgme_data_seek(out.get(), 0, SEEK_SET);
  string s{};
  while ((ret = gpgme_data_read(out.get(), buf, buffsize)) > 0) {
    buf[ret] = '\0';
    s += string{buf};
  }
  ASSERT_EQ(s.find("-----BEGIN PGP MESSAGE-----"s), 0);
  ASSERT_NE(s.find("-----END PGP MESSAGE-----"s), string::npos);

  gpgme_data_raii cip{s};
  gpgme_data_raii dec{};
  char buf2[buffsize + 1] = "";

  gpgme_op_decrypt_ext(c.get(), static_cast<gpgme_decrypt_flags_t>(0),
                       cip.get(), dec.get());
  ret = gpgme_data_seek(dec.get(), 0, SEEK_SET);
  stringstream ss{};
  while ((ret = gpgme_data_read(dec.get(), buf2, buffsize)) > 0) {
    ss << string{buf2};
  }
  ASSERT_EQ(ss.str(), str);
}

TEST(unitTests, getNonce_length) {
  for (int i{1}; i < 30; i++)
    ASSERT_EQ(getNonce(i).length(), i);
}

TEST(unitTests, getNonce_unique) {
  vector<string> all{};
  for (int i{0}; i < 50; i++)
    all.push_back(getNonce(10));

  sort(all.begin(), all.end());
  vector<string> uniq(all.begin(), unique(all.begin(), all.end()));
  ASSERT_EQ(all.size(), uniq.size());
}

TEST(unitTests, mhdRespRaii) {
  auto tmp{"some response body"s};
  mhdRespRaii r{tmp};

  ASSERT_NE(nullptr, r.get());
}

TEST(unitTests, encrypter_create) {
  ASSERT_NO_THROW(encrypter e("some plaintext"s, "~/.gnupg"s));
}

TEST(unitTests, encrypter_operate) {
  encrypter e("some plaintext"s, "~/.gnupg"s);
  auto tmp{e.ciphertext(validEmail, false, false, ""s)};
  ASSERT_EQ(tmp.find("-----BEGIN PGP MESSAGE-----"s), 0);
  ASSERT_NE(tmp.find("-----END PGP MESSAGE-----"s), string::npos);
}

/*
  Currently untested:
  converse(): need a pam module to call into, knwon to work in a real module
  privDropper: need to run a test as root to see it working
 */
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
