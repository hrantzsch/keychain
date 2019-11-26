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

#include <memory>

#define UNICODE

#include <windows.h>
#include <wincred.h>
#include <intsafe.h> // for DWORD_MAX
// clang-format on

namespace {

static DWORD cred_type = CRED_TYPE_GENERIC;

struct LpwstrDeleter {
    void operator()(WCHAR *p) const { delete[] p; }
};
using ScopedLpwstr = std::unique_ptr<WCHAR, LpwstrDeleter>;

LPWSTR utf8ToWideChar(const std::string &utf8) {
    int len = MultiByteToWideChar(
        CP_UTF8,
        0, // flags must be 0 for UTF-8
        utf8.c_str(),
        -1,      // rely on null-terminated input string
        nullptr, // no out-buffer needed
        0); // return required buffer size rather than writing to an out-buffer
    if (len == 0) {
        return nullptr;
    }

    LPWSTR buffer = new WCHAR[len];
    int bytesWritten =
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, buffer, len);

    if (bytesWritten == 0) {
        // failure; cleanup buffer manually
        delete[] buffer;
        return nullptr;
    }

    return buffer;
}

std::string wideCharToAnsi(LPWSTR wChar) {
    std::string result;
    if (wChar == nullptr) {
        return result;
    }

    int len =
        WideCharToMultiByte(CP_ACP, 0, wChar, -1, nullptr, 0, nullptr, nullptr);
    if (len == 0) {
        return result;
    }

    std::unique_ptr<char[]> buffer(new char[len]);
    int bytesWritten = WideCharToMultiByte(
        CP_ACP, 0, wChar, -1, buffer.get(), len, nullptr, nullptr);

    if (bytesWritten != 0) {
        result = std::string(buffer.get());
    }

    return result;
}

std::string getErrorMessage(DWORD errorCode) {
    std::string errMsg;
    LPWSTR errBuffer = nullptr;
    ::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                    nullptr, // ignored for the flags we use
                    errorCode,
                    0, // figure out LANGID automatically
                    reinterpret_cast<LPWSTR>(&errBuffer),
                    0,        // figure out out-buffer size automatically
                    nullptr); // no additional arguments
    if (errBuffer != nullptr) {
        errMsg = wideCharToAnsi(errBuffer);
        LocalFree(errBuffer);
    }
    return errMsg;
}

std::string makeTargetName(const std::string &package,
                           const std::string &service,
                           const std::string &user) {
    return package + "." + service + '/' + user;
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

    ScopedLpwstr target_name(
        utf8ToWideChar(makeTargetName(package, service, user)));
    if (!target_name) {
        updateError(err);
        return;
    }

    ScopedLpwstr user_name(utf8ToWideChar(user));
    if (!user_name) {
        updateError(err);
        return;
    }

    if (password.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE ||
        password.size() > DWORD_MAX) {
        err.error = KeychainError::PasswordTooLong;
        err.message = "Password too long.";
        err.code = -1; // generic non-zero
        return;
    }

    CREDENTIAL cred = {0};
    cred.Type = cred_type;
    cred.TargetName = target_name.get();
    cred.UserName = user_name.get();
    cred.CredentialBlobSize = static_cast<DWORD>(password.size());
    cred.CredentialBlob = (LPBYTE)(password.data());
    cred.Persist = CRED_PERSIST_ENTERPRISE;

    ::CredWrite(&cred, 0);
    updateError(err);
}

std::string getPassword(const std::string &package, const std::string &service,
                        const std::string &user, Error &err) {
    ::SetLastError(0); // clear thread-global error
    std::string password;

    ScopedLpwstr target_name(
        utf8ToWideChar(makeTargetName(package, service, user)));
    if (!target_name) {
        updateError(err);
        return password;
    }

    CREDENTIAL *cred;
    bool result = ::CredRead(target_name.get(), cred_type, 0, &cred);
    updateError(err);

    if (!err && result) {
        password = std::string(reinterpret_cast<char *>(cred->CredentialBlob),
                               cred->CredentialBlobSize);
        ::CredFree(cred);
    }
    return password;
}

void deletePassword(const std::string &package, const std::string &service,
                    const std::string &user, Error &err) {
    ::SetLastError(0); // clear thread-global error

    ScopedLpwstr target_name(
        utf8ToWideChar(makeTargetName(package, service, user)));
    if (target_name) {
        ::CredDelete(target_name.get(), cred_type, 0);
    }
    updateError(err);
}

} // namespace keychain
