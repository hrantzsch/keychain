#include "catch.hpp"
#include "keychain.h"
#include "keytar.h"

TEST_CASE("Keytar", "[keytar]") {
    auto crud = [](const std::string &service, const std::string &account,
                   const std::string &password_in) {
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

TEST_CASE("Keychain", "[keychain]") {
    using Keychain = keychain::Keychain;

    auto crud = [](Keychain k, const std::string &password_in) {
        REQUIRE(!k.getPassword().has_value());
        CHECK(k.setPassword(password_in));

        auto password_out = k.getPassword();
        CHECK(k.getPassword().has_value());
        CHECK(password_out.value() == password_in);

        const std::string better_password =
            "123456 is the No. 1 top rated password in 2019 again!";
        CHECK(k.setPassword(better_password));
        password_out = k.getPassword();
        CHECK(k.getPassword().has_value());
        CHECK(password_out.value() == better_password);

        CHECK(k.deletePassword());
        CHECK(!k.getPassword().has_value());
    };

    const std::string service = "keytar_test";
    const std::string account = "Admin";
    const std::string password = "hunter2";

    SECTION("the happily place") { crud(Keychain(service, account), password); }

    SECTION("empty service name") { crud(Keychain("", account), password); }
    SECTION("empty account name") { crud(Keychain(service, ""), password); }
    SECTION("empty password") { crud(Keychain(service, account), ""); }

    SECTION("long password") {
        const std::string long_pw(4097, '=');
        crud(Keychain(service, account), long_pw);
    }
}
