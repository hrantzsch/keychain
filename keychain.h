#ifndef KEYCHAIN_H
#define KEYCHAIN_H

#include <string>

namespace keychain {

enum class KeychainError {
    NoError = 0,
    NotFound = 10, // requested password was not found
    AccessDenied,
    GenericError,
};

struct Error {
    KeychainError error;
    std::string message;
    int code;

    operator bool() { return KeychainError::NoError != error; }
};

std::string getPassword(const std::string &package, const std::string &service,
                        const std::string &user, Error &err);

void setPassword(const std::string &package, const std::string &service,
                 const std::string &user, const std::string &password,
                 Error &err);

void deletePassword(const std::string &package, const std::string &service,
                    const std::string &user, Error &err);

} // namespace keychain

#endif
