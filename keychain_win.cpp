/*
 * Copyright (c) 2013 GitHub Inc.
 * Copyright (c) 2019 Hannes Rantzsch
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

// clang-format off
// make sure windows.h is included before wincred.h
#include "keychain.h"

#define UNICODE

#include <windows.h>
#include <wincred.h>
// clang-format on

namespace {

static DWORD cred_type = CRED_TYPE_GENERIC;

LPWSTR utf8ToWideChar(const std::string &utf8) {
    int wide_char_length =
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    if (wide_char_length == 0) {
        return NULL;
    }

    LPWSTR result = new WCHAR[wide_char_length];
    if (MultiByteToWideChar(
            CP_UTF8, 0, utf8.c_str(), -1, result, wide_char_length) == 0) {
        delete[] result;
        return NULL;
    }

    return result;
}

std::string wideCharToAnsi(LPWSTR wide_char) {
    if (wide_char == NULL) {
        return std::string();
    }

    int ansi_length =
        WideCharToMultiByte(CP_ACP, 0, wide_char, -1, NULL, 0, NULL, NULL);
    if (ansi_length == 0) {
        return std::string();
    }

    char *buffer = new char[ansi_length];
    if (WideCharToMultiByte(
            CP_ACP, 0, wide_char, -1, buffer, ansi_length, NULL, NULL) == 0) {
        delete[] buffer;
        return std::string();
    }

    std::string result = std::string(buffer);
    delete[] buffer;
    return result;
}

std::string wideCharToUtf8(LPWSTR wide_char) {
    if (wide_char == NULL) {
        return std::string();
    }

    int utf8_length =
        WideCharToMultiByte(CP_UTF8, 0, wide_char, -1, NULL, 0, NULL, NULL);
    if (utf8_length == 0) {
        return std::string();
    }

    char *buffer = new char[utf8_length];
    if (WideCharToMultiByte(
            CP_UTF8, 0, wide_char, -1, buffer, utf8_length, NULL, NULL) == 0) {
        delete[] buffer;
        return std::string();
    }

    std::string result = std::string(buffer);
    delete[] buffer;
    return result;
}

LPWSTR makeTargetName(const std::string &package, const std::string &service,
                      const std::string &user) {
    return utf8ToWideChar(package + "." + service + '/' + user);
}

std::string getErrorMessage(DWORD errorCode) {
    LPWSTR errBuffer;
    ::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                    NULL,
                    errorCode,
                    0,
                    (LPWSTR)&errBuffer,
                    0,
                    NULL);
    std::string errMsg = wideCharToAnsi(errBuffer);
    LocalFree(errBuffer);
    return errMsg;
}

void updateError(keychain::Error &err) {
    const auto code = ::GetLastError();
    if (code == ERROR_SUCCESS) {
        err = keychain::Error{};
        return;
    }

    err.message = getErrorMessage(code);
    err.code = code;
    err.error = err.code == ERROR_NOT_FOUND
                    ? keychain::KeychainError::NotFound
                    : keychain::KeychainError::GenericError;
}

} // namespace

namespace keychain {

void setPassword(const std::string &package, const std::string &service,
                 const std::string &user, const std::string &password,
                 Error &err) {
    ::SetLastError(0); // clear thread-global error

    LPWSTR target_name = makeTargetName(package, service, user);
    if (target_name == NULL) {
        updateError(err);
        return;
    }

    LPWSTR user_name = utf8ToWideChar(user);
    if (user_name == NULL) {
        updateError(err);
        return;
    }

    if (password.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE) {
        err.error = KeychainError::PasswordTooLong;
        err.message = "Password too long.";
        err.code = -1; // generic non-zero
        return;
    }

    CREDENTIAL cred = {0};
    cred.Type = cred_type;
    cred.TargetName = target_name;
    cred.UserName = user_name;
    cred.CredentialBlobSize = password.size();
    cred.CredentialBlob = (LPBYTE)(password.data());
    cred.Persist = CRED_PERSIST_ENTERPRISE;

    ::CredWrite(&cred, 0);
    delete[] target_name;
    updateError(err);
}

std::string getPassword(const std::string &package, const std::string &service,
                        const std::string &user, Error &err) {
    LPWSTR target_name = makeTargetName(package, service, user);
    if (target_name == NULL) {
        updateError(err);
        return "";
    }

    CREDENTIAL *cred;
    bool result = ::CredRead(target_name, cred_type, 0, &cred);
    delete[] target_name;

    updateError(err);
    if (err || !result) {
        if (cred != nullptr) {
            ::CredFree(cred);
        }
        return "";
    }

    std::string password(reinterpret_cast<char *>(cred->CredentialBlob),
                         cred->CredentialBlobSize);
    ::CredFree(cred);
    return password;
}

void deletePassword(const std::string &package, const std::string &service,
                    const std::string &user, Error &err) {
    LPWSTR target_name = makeTargetName(package, service, user);
    if (target_name == NULL) {
        updateError(err);
        return;
    }

    ::CredDelete(target_name, cred_type, 0);
    delete[] target_name;
    updateError(err);
}

} // namespace keychain
