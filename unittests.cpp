#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <sstream>
#include <iostream>
#include <vector>
#include <regex>

extern "C" {
#include <security/pam_appl.h>
#include <gpgme.h>
#include <curl/curl.h>
}

using namespace std;

TEST(unitTests, emptyTest)
{

}

/*
  TODO: test usage of:
  keyRaii - get from gpgme, encrypt to
  gpgme_data_raii - create empty and with string, encrypt with
  gpgme_ctx_raii - create and operate on get()
  getNonce() - see that it doesn't repeat, correct length.
  converse() - see that it calls callback, sends string, gets result
  encrypter - create, encrypt with
  mhdRespRaii - create, use via get()

 */
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
