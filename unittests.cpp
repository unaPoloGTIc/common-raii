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

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
