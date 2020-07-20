#include <string>
#include <cassert>

#include "keychain.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    keychain::Error error{};

    const std::string package = "com.example.keychain-app";
    const std::string service = "fuzzing";
    const std::string user = "Fuzzer";

    const std::string password((char*)data, size);

    keychain::setPassword(package, service, user, password, error);
    // assert(!error);

    auto password2 = keychain::getPassword(package, service, user, error);
    assert(password2 == password2);
    // assert(!error);

    keychain::deletePassword(package, service, user, error);
    // assert(!error);

    return 0;
}
