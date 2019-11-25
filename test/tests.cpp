#include "catch.hpp"
#include "keychain.h"

using namespace keychain;

CATCH_REGISTER_ENUM(keychain::KeychainError, keychain::KeychainError::NoError,
                    keychain::KeychainError::NotFound,
                    keychain::KeychainError::AccessDenied,
                    keychain::KeychainError::GenericError)

void check_no_error(const Error &ec) {
    const std::string error =
        Catch::StringMaker<keychain::KeychainError>::convert(ec.error);
    INFO(error << " [" << ec.code << "] "
               << ": " << ec.message);
    CHECK(!ec);
};

TEST_CASE("Keychain", "[keychain]") {
    auto crud = [](const std::string &package,
                   const std::string &service,
                   const std::string &user,
                   const std::string &password_in) {
        Error ec{};
        getPassword(package, service, user, ec);
        REQUIRE(ec.error == KeychainError::NotFound);

        ec = Error{};
        setPassword(package, service, user, password_in, ec);
        check_no_error(ec);

        ec = Error{};
        auto password = getPassword(package, service, user, ec);
        check_no_error(ec);
        CHECK(password == password_in);

        const std::string better_password = "123456";

        ec = Error{};
        setPassword(package, service, user, better_password, ec);
        check_no_error(ec);

        ec = Error{};
        password = getPassword(package, service, user, ec);
        REQUIRE(!ec);
        CHECK(password == better_password);

        ec = Error{};
        deletePassword(package, service, user, ec);
        check_no_error(ec);
        ec = Error{};
        getPassword(package, service, user, ec);
        CHECK(ec.error == KeychainError::NotFound);
    };

    const std::string package = "com.example.keychain-tests";
    const std::string service = "test_service";
    const std::string user = "Admin";
    const std::string password = "hunter2";

    SECTION("the happily place") { crud(package, service, user, password); }

    SECTION("empty service name") { crud(package, "", user, password); }
    SECTION("empty user name") { crud(package, service, "", password); }
    SECTION("empty password") { crud(package, service, user, ""); }
    SECTION("both service and user name empty") {
        crud(package, "", "", password);
    }

    SECTION("long password") {
        const std::string long_pw(4097, '=');
        crud(package, service, user, long_pw);
    }
    SECTION("unicode") { crud("🙈.🙉.🙊", "💛", "👩💻", "🔑"); }
}
