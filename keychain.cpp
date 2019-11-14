#include "keychain.h"

using namespace keychain;

Keychain::Keychain(const std::string &service, const std::string &user)
    : _service(makeServiceName(service)), _user(user) {}

std::optional<std::string> Keychain::getPassword() {
    clearError();

    auto result = Keychain::getPassword(_service, _user);

    // should either return a Password or an Error
    assert(!std::holds_alternative<Keychain::Success>(result));

    auto err = std::get_if<Keychain::Error>(&result);
    if (err) {
        _lastError = err->message;
        return std::nullopt;
    }
    return std::get<Keychain::Password>(result);
}

template <typename F>
bool Keychain::updatePassword(F &&updateFun) {
    clearError();

    auto result = updateFun();

    // should either return a Success or an Error
    assert(!std::holds_alternative<Keychain::Success>(result));

    auto err = std::get_if<Keychain::Error>(&result);
    if (err) _lastError = err->message;
    return !err;
}

bool Keychain::setPassword(const std::string &password) {
    return updatePassword([s = _service, u = _user, p = password] {
        return Keychain::setPassword(s, u, p);
    });
}

bool Keychain::deletePassword() {
    return updatePassword(
        [s = _service, u = _user] { return Keychain::deletePassword(s, u); });
}

void Keychain::clearError() { _lastError = std::nullopt; }

// TODO: platform specific implementations using keytar

std::string Keychain::makeServiceName(const std::string &s) const { return s; }

Keychain::Result Keychain::getPassword(const std::string &service,
                                       const std::string &user) {
    return Keychain::Error{"nyi"};
}

Keychain::Result Keychain::setPassword(const std::string &service,
                                       const std::string &user,
                                       const std::string &password) {
    return Keychain::Error{"nyi"};
}
Keychain::Result Keychain::deletePassword(const std::string &service,
                                          const std::string &user) {
    return Keychain::Error{"nyi"};
}
