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

void handleCFCreateFailure(keychain::Error &err,
                           const std::string &errorMessage) {
    err.message = errorMessage;
    err.type = keychain::ErrorType::GenericError;
    err.code = -1;
}

CFStringRef createCFStringWithCString(const std::string &str,
                                      keychain::Error &err) {
    CFStringRef result = CFStringCreateWithCString(
        kCFAllocatorDefault, str.c_str(), kCFStringEncodingUTF8);
    if (result == NULL) {
        handleCFCreateFailure(err, "Failed to create CFString");
    }
    return result;
}

CFMutableDictionaryRef createCFMutableDictionary(keychain::Error &err) {
    CFMutableDictionaryRef result =
        CFDictionaryCreateMutable(kCFAllocatorDefault,
                                  0,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    if (result == NULL) {
        handleCFCreateFailure(err, "Failed to create CFMutableDictionary");
    }
    return result;
}

CFDataRef createCFData(const std::string &data, keychain::Error &err) {
    CFDataRef result =
        CFDataCreate(kCFAllocatorDefault,
                     reinterpret_cast<const UInt8 *>(data.c_str()),
                     data.length());
    if (result == NULL) {
        handleCFCreateFailure(err, "Failed to create CFData");
    }
    return result;
}

CFMutableDictionaryRef createQuery(const std::string &serviceName,
                                   const std::string &user,
                                   keychain::Error &err) {
    CFStringRef cfServiceName = createCFStringWithCString(serviceName, err);
    CFStringRef cfUser = createCFStringWithCString(user, err);
    CFMutableDictionaryRef query = createCFMutableDictionary(err);

    if (err.type != keychain::ErrorType::NoError) {
        if (cfServiceName)
            CFRelease(cfServiceName);
        if (cfUser)
            CFRelease(cfUser);
        return NULL;
    }

    CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrAccount, cfUser);
    CFDictionaryAddValue(query, kSecAttrService, cfServiceName);

    CFRelease(cfServiceName);
    CFRelease(cfUser);

    return query;
}

} // namespace

namespace keychain {

void setPassword(const std::string &package, const std::string &service,
                 const std::string &user, const std::string &password,
                 Error &err) {
    err = Error{};
    const auto serviceName = makeServiceName(package, service);
    CFDataRef cfPassword = createCFData(password, err);
    CFMutableDictionaryRef query = createQuery(serviceName, user, err);

    if (err.type != keychain::ErrorType::NoError) {
        return;
    }

    CFDictionaryAddValue(query, kSecValueData, cfPassword);

    OSStatus status = SecItemAdd(query, NULL);

    if (status == errSecDuplicateItem) {
        // password exists -- override
        CFMutableDictionaryRef attributesToUpdate =
            createCFMutableDictionary(err);
        if (err.type != keychain::ErrorType::NoError) {
            CFRelease(cfPassword);
            CFRelease(query);
            return;
        }

        CFDictionaryAddValue(attributesToUpdate, kSecValueData, cfPassword);
        status = SecItemUpdate(query, attributesToUpdate);

        CFRelease(attributesToUpdate);
    }

    if (status != errSecSuccess) {
        updateError(err, status);
    }

    CFRelease(cfPassword);
    CFRelease(query);
}

std::string getPassword(const std::string &package, const std::string &service,
                        const std::string &user, Error &err) {
    err = Error{};
    std::string password;
    const auto serviceName = makeServiceName(package, service);
    CFMutableDictionaryRef query = createQuery(serviceName, user, err);

    if (err.type != keychain::ErrorType::NoError) {
        return password;
    }

    CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);

    if (status != errSecSuccess) {
        updateError(err, status);
    } else if (result != NULL) {
        CFDataRef cfPassword = (CFDataRef)result;
        password = std::string(
            reinterpret_cast<const char *>(CFDataGetBytePtr(cfPassword)),
            CFDataGetLength(cfPassword));
        CFRelease(result);
    }

    CFRelease(query);

    return password;
}

void deletePassword(const std::string &package, const std::string &service,
                    const std::string &user, Error &err) {
    err = Error{};
    const auto serviceName = makeServiceName(package, service);
    CFMutableDictionaryRef query = createQuery(serviceName, user, err);

    if (err.type != keychain::ErrorType::NoError) {
        return;
    }

    OSStatus status = SecItemDelete(query);

    if (status != errSecSuccess) {
        updateError(err, status);
    }

    CFRelease(query);
}

} // namespace keychain
