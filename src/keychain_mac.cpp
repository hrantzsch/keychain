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
/*! \brief Converts a CFString to a std::string
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

//! \brief Extracts a human readable string from a status code
std::string errorStatusToString(OSStatus status) {
    const auto errorMessage = SecCopyErrorMessageString(status, NULL);
    std::string errorString;

    if (errorMessage) {
        errorString = CFStringToStdString(errorMessage);
        CFRelease(errorMessage);
    }

    return errorString;
}

std::string makeServiceName(const std::string &package,
                            const std::string &service) {
    return package + "." + service;
}

/*! \brief Update error information
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
    err.code = status;

    switch (status) {
    case errSecItemNotFound:
        err.type = keychain::ErrorType::NotFound;
        break;

    // potential errors in case the user needs to unlock the keychain first
    case errSecUserCanceled:        // user pressed the Cancel button
    case errSecAuthFailed:          // too many failed password attempts
    case errSecInteractionRequired: // user interaction required but not allowed
        err.type = keychain::ErrorType::AccessDenied;
        break;

    default:
        err.type = keychain::ErrorType::GenericError;
    }
}

/*! \brief Modify an existing password
 *
 * Helper function that tries to find an existing password in the keychain and
 * modifies it.
 */
OSStatus modifyPassword(const std::string &serviceName, const std::string &user,
                        const std::string &password) {
    CFStringRef cfServiceName = CFStringCreateWithCString(NULL, serviceName.c_str(), kCFStringEncodingUTF8);
    CFStringRef cfUser = CFStringCreateWithCString(NULL, user.c_str(), kCFStringEncodingUTF8);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrAccount, cfUser);
    CFDictionaryAddValue(query, kSecAttrService, cfServiceName);

    CFDataRef cfPassword = CFDataCreate(NULL, reinterpret_cast<const UInt8 *>(password.c_str()), password.length());
    CFMutableDictionaryRef attributesToUpdate = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(attributesToUpdate, kSecValueData, cfPassword);

    OSStatus status = SecItemUpdate(query, attributesToUpdate);

    CFRelease(cfServiceName);
    CFRelease(cfUser);
    CFRelease(cfPassword);
    CFRelease(query);
    CFRelease(attributesToUpdate);

    return status;
}

} // namespace

namespace keychain {

void setPassword(const std::string &package, const std::string &service,
                 const std::string &user, const std::string &password,
                 Error &err) {
    err = Error{};
    const auto serviceName = makeServiceName(package, service);

    CFStringRef cfServiceName = CFStringCreateWithCString(NULL, serviceName.c_str(), kCFStringEncodingUTF8);
    CFStringRef cfUser = CFStringCreateWithCString(NULL, user.c_str(), kCFStringEncodingUTF8);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrAccount, cfUser);
    CFDictionaryAddValue(query, kSecAttrService, cfServiceName);

    CFDataRef cfPassword = CFDataCreate(NULL, reinterpret_cast<const UInt8 *>(password.c_str()), password.length());
    CFDictionaryAddValue(query, kSecValueData, cfPassword);

    OSStatus status = SecItemAdd(query, NULL);

    if (status == errSecDuplicateItem) {
        // password exists -- override
        status = modifyPassword(serviceName, user, password);
    }

    if (status != errSecSuccess) {
        updateError(err, status);
    }

    CFRelease(cfServiceName);
    CFRelease(cfUser);
    CFRelease(cfPassword);
    CFRelease(query);
}

std::string getPassword(const std::string &package, const std::string &service,
                        const std::string &user, Error &err) {
    err = Error{};
    const auto serviceName = makeServiceName(package, service);

    CFStringRef cfServiceName = CFStringCreateWithCString(NULL, serviceName.c_str(), kCFStringEncodingUTF8);
    CFStringRef cfUser = CFStringCreateWithCString(NULL, user.c_str(), kCFStringEncodingUTF8);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrAccount, cfUser);
    CFDictionaryAddValue(query, kSecAttrService, cfServiceName);
    CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    std::string password;

    if (status != errSecSuccess) {
        updateError(err, status);
    } else if (result != NULL) {
        CFDataRef cfPassword = (CFDataRef)result;
        password = std::string(reinterpret_cast<const char *>(CFDataGetBytePtr(cfPassword)), CFDataGetLength(cfPassword));
        CFRelease(result);
    }

    CFRelease(cfServiceName);
    CFRelease(cfUser);
    CFRelease(query);

    return password;
}

void deletePassword(const std::string &package, const std::string &service,
                    const std::string &user, Error &err) {
    err = Error{};
    const auto serviceName = makeServiceName(package, service);

    CFStringRef cfServiceName = CFStringCreateWithCString(NULL, serviceName.c_str(), kCFStringEncodingUTF8);
    CFStringRef cfUser = CFStringCreateWithCString(NULL, user.c_str(), kCFStringEncodingUTF8);

    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrAccount, cfUser);
    CFDictionaryAddValue(query, kSecAttrService, cfServiceName);

    OSStatus status = SecItemDelete(query);

    if (status != errSecSuccess) {
        updateError(err, status);
    }

    CFRelease(cfServiceName);
    CFRelease(cfUser);
    CFRelease(query);
}

} // namespace keychain
