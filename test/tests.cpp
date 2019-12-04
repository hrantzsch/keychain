#include "catch.hpp"
#include "keychain.h"

using namespace keychain;

CATCH_REGISTER_ENUM(keychain::KeychainError, keychain::KeychainError::NoError,
                    keychain::KeychainError::GenericError,
                    keychain::KeychainError::NotFound,
                    keychain::KeychainError::PasswordTooLong,
                    keychain::KeychainError::AccessDenied)

void check_no_error(const Error &ec) {
    const std::string error =
        Catch::StringMaker<keychain::KeychainError>::convert(ec.error);
    INFO(error << " [" << ec.code << "] "
               << ": " << ec.message);
    CHECK(!ec);
}

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

    SECTION("empty package name") { crud(package, "", user, password); }
    SECTION("empty service name") { crud(package, "", user, password); }
    SECTION("empty user name") { crud(package, service, "", password); }
    SECTION("empty password") { crud(package, service, user, ""); }
    SECTION("all empty") { crud("", "", "", ""); }

#ifdef KEYCHAIN_WINDOWS
    // Windows will report an error, other platforms succeed
    SECTION("long password (windows)") {
        const std::string longPassword(4097, '=');
        Error ec{};
        getPassword(package, service, user, ec);
        REQUIRE(ec.error == KeychainError::NotFound);

        ec = Error{};
        setPassword(package, service, user, longPassword, ec);
        CHECK(ec.error == KeychainError::PasswordTooLong);
    }
#else
    SECTION("long password (unix)") {
        const std::string longPassword(4097, '=');
        crud(package, service, user, longPassword);
    }
#endif

    SECTION("unicode") { crud("🙈.🙉.🙊", "💛", "👩💻", "🔑"); }
}
