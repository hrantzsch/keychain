#include "catch.hpp"
#include "keytar.h"

TEST_CASE("Keytar", "[keytar]") {
    auto crud = [](const std::string &service, const std::string &account,
                  const std::string &password_in) {
        // The original Keytar returns passwords and reports errors as out-
        // parameters. This fork does not set an error string (which never
        // worked for me with the original Keytar anyway), but still uses the
        // out-parameter. I'll be glad to change this interface.
        std::string password_out;

        REQUIRE(!keytar::GetPassword(service, account, &password_out));
        CHECK(keytar::AddPassword(service, account, password_in));

        CHECK(keytar::GetPassword(service, account, &password_out));
        CHECK(password_out == password_in);

        const std::string better_password =
            "123456 is the No. 1 top rated password in 2019 again!";
        // Note that this is probably a really good password. Sorry to ruin it.
        CHECK(keytar::AddPassword(service, account, better_password));
        CHECK(keytar::GetPassword(service, account, &password_out));
        CHECK(password_out == better_password);

        CHECK(keytar::DeletePassword(service, account));
        CHECK(!keytar::GetPassword(service, account, &password_out));
    };

    const std::string service = "keytar_test";
    const std::string account = "Admin";
    const std::string password = "hunter2";

    SECTION("the happily place") { crud(service, account, password); }

    SECTION("empty service name") { crud("", account, password); }
    SECTION("empty account name") { crud(service, "", password); }
    SECTION("empty password") { crud(service, account, ""); }

    SECTION("long password") {
        const std::string long_pw(4097, '=');
        crud(service, account, long_pw);
    }
}
