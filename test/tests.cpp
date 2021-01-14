#include "catch.hpp"
#include "keychain/keychain.h"

using namespace keychain;

// clang-format off
CATCH_REGISTER_ENUM(keychain::ErrorType,
                    keychain::ErrorType::NoError,
                    keychain::ErrorType::GenericError,
                    keychain::ErrorType::NotFound,
                    keychain::ErrorType::PasswordTooLong,
                    keychain::ErrorType::AccessDenied)
// clang-format on

void check_no_error(const Error &ec) {
    const std::string error =
        Catch::StringMaker<keychain::ErrorType>::convert(ec.type);
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
        REQUIRE(ec.type == ErrorType::NotFound);

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
        CHECK(ec.type == ErrorType::NotFound);
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
        REQUIRE(ec.type == ErrorType::NotFound);

        ec = Error{};
        setPassword(package, service, user, longPassword, ec);
        CHECK(ec.type == ErrorType::PasswordTooLong);
    }
#else
    SECTION("long password (unix)") {
        const std::string longPassword(4097, '=');
        crud(package, service, user, longPassword);
    }
#endif

    SECTION("unicode") { crud("🙈.🙉.🙊", "💛", "👩💻", "🔑"); }

    SECTION("deleting a password that does not exist results in NotFound") {
        Error ec{};
        deletePassword("no.package", "no.service", "no.user", ec);
        CHECK(ec.type == ErrorType::NotFound);
    }

    SECTION("successful function call overrides previous Error to success") {
        Error ec{};
        ec.type = ErrorType::GenericError;
        setPassword(package, service, user, password, ec);
        check_no_error(ec);

        ec.type = ErrorType::GenericError;
        getPassword(package, service, user, ec);
        check_no_error(ec);

        ec.type = ErrorType::GenericError;
        deletePassword(package, service, user, ec);
        check_no_error(ec);
    }
}
