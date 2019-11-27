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

#include <vector>

#include <Security/Security.h>

#include "keychain.h"

namespace {

/*!
 * Converts a CFString to a std::string
 *
 * This either uses CFStringGetCStringPtr or (if that fails) CFStringGetCString.
 */
std::string CFStringToStdString(const CFStringRef cfstring) {
    const char *ccstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8);

    if (ccstr != nullptr) {
        return std::string(ccstr);
    }

    auto utf16Pairs = CFStringGetLength(cfstring);
    auto maxUtf8Bytes =
        CFStringGetMaximumSizeForEncoding(utf16Pairs, kCFStringEncodingUTF8);

    std::vector<char> cstr(maxUtf8Bytes, '\0');
    auto result = CFStringGetCString(
        cfstring, cstr.data(), cstr.size(), kCFStringEncodingUTF8);

    return result ? std::string(cstr.data()) : std::string();
}

std::string errorStatusToString(OSStatus status) {
    std::string errorStr;
    CFStringRef errorMessageString = SecCopyErrorMessageString(status, NULL);

    const char *errorCStringPtr =
        CFStringGetCStringPtr(errorMessageString, kCFStringEncodingUTF8);
    if (errorCStringPtr) {
        errorStr = std::string(errorCStringPtr);
    } else {
        errorStr = std::string("An unknown error occurred.");
    }

    CFRelease(errorMessageString);
    return errorStr;
}

std::string makeServiceName(const std::string &package,
                            const std::string &service) {
    return package + "." + service;
}

/*!
 * Update error information
 *
 * If status indicates an error condition, set message, code and error type.
 * Otherwise, set err to success.
 */
void updateError(keychain::Error &err, OSStatus status) {
    if (status == errSecSuccess) {
        err = keychain::Error{};
        return;
    }

    err.message = errorStatusToString(status);
    err.code = status; // TODO check conversion
    err.error = status == errSecItemNotFound
                    ? keychain::KeychainError::NotFound
                    : keychain::KeychainError::GenericError;
}

/*!
 * Modify an existing password
 *
 * Helper function that tries to find an existing password in the keychain and
 * modifies it.
 */
OSStatus modifyPassword(const std::string &serviceName, const std::string &user,
                        const std::string &password) {
    SecKeychainItemRef item = NULL;
    OSStatus status =
        SecKeychainFindGenericPassword(NULL,
                                       (UInt32)serviceName.length(),
                                       serviceName.data(),
                                       (UInt32)user.length(),
                                       user.data(),
                                       NULL,
                                       NULL,
                                       &item);
    if (status == errSecSuccess) {
        status = SecKeychainItemModifyContent(
            item, NULL, (UInt32)password.length(), password.data());
    }

    if (item) {
        CFRelease(item);
    }

    return status;
}

} // namespace

namespace keychain {

void setPassword(const std::string &package, const std::string &service,
                 const std::string &user, const std::string &password,
                 Error &err) {
    const auto serviceName = makeServiceName(package, service);
    OSStatus status =
        SecKeychainAddGenericPassword(NULL,
                                      (UInt32)serviceName.length(),
                                      serviceName.data(),
                                      (UInt32)user.length(),
                                      user.data(),
                                      (UInt32)password.length(),
                                      password.data(),
                                      NULL);

    if (status == errSecDuplicateItem) {
        // password exists -- override
        status = modifyPassword(serviceName, user, password);
    }

    updateError(err, status);
}

std::string getPassword(const std::string &package, const std::string &service,
                        const std::string &user, Error &err) {
    const auto serviceName = makeServiceName(package, service);
    void *data;
    UInt32 length;
    OSStatus status =
        SecKeychainFindGenericPassword(NULL,
                                       (UInt32)serviceName.length(),
                                       serviceName.data(),
                                       (UInt32)user.length(),
                                       user.data(),
                                       &length,
                                       &data,
                                       NULL);

    updateError(err, status);
    if (err || data == NULL) {
        return "";
    }

    std::string password(reinterpret_cast<const char *>(data), length);
    SecKeychainItemFreeContent(NULL, data);
    return password;
}

void deletePassword(const std::string &package, const std::string &service,
                    const std::string &user, Error &err) {
    const auto serviceName = makeServiceName(package, service);
    SecKeychainItemRef item;
    OSStatus status =
        SecKeychainFindGenericPassword(NULL,
                                       (UInt32)serviceName.length(),
                                       serviceName.data(),
                                       (UInt32)user.length(),
                                       user.data(),
                                       NULL,
                                       NULL,
                                       &item);
    updateError(err, status);
    if (!err) {
        status = SecKeychainItemDelete(item);
        updateError(err, status);
    }

    CFRelease(item);
}

} // namespace keychain
