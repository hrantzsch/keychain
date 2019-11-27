/*
 * Copyright (c) 2013 GitHub Inc.
 * Copyright (c) 2015-2019 Vaclav Slavik
 * Copyright (c) 2019 Hannes Rantzsch, René Meusel
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

#include "keychain.h"

#include <libsecret/secret.h>

namespace keychain {

const char *ServiceFieldName = "service";
const char *AccountFieldName = "username";

// disable warnings about missing initializers in SecretSchema
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

const SecretSchema makeSchema(const std::string &package) {
    return SecretSchema{package.c_str(),
                        SECRET_SCHEMA_NONE,
                        {
                            {ServiceFieldName, SECRET_SCHEMA_ATTRIBUTE_STRING},
                            {AccountFieldName, SECRET_SCHEMA_ATTRIBUTE_STRING},
                            {NULL, SecretSchemaAttributeType(0)},
                        }};
}

void setPassword(const std::string &package, const std::string &service,
                 const std::string &user, const std::string &password,
                 Error &err) {
    const auto schema = makeSchema(package);
    GError *error = NULL;

    std::string label = service;
    if (!user.empty())
        label += " (" + user + ")";

    secret_password_store_sync(&schema,
                               SECRET_COLLECTION_DEFAULT,
                               label.c_str(),
                               password.c_str(),
                               NULL, // not cancellable
                               &error,
                               ServiceFieldName,
                               service.c_str(),
                               AccountFieldName,
                               user.c_str(),
                               NULL);

    if (error != NULL) {
        err.error = KeychainError::GenericError;
        err.message = error->message;
        err.code = error->code;
        g_error_free(error);
    }
}

std::string getPassword(const std::string &package, const std::string &service,
                        const std::string &user, Error &err) {
    const auto schema = makeSchema(package);
    GError *error = NULL;

    gchar *raw_passwords;
    raw_passwords = secret_password_lookup_sync(&schema,
                                                NULL, // not cancellable
                                                &error,
                                                ServiceFieldName,
                                                service.c_str(),
                                                AccountFieldName,
                                                user.c_str(),
                                                NULL);

    std::string password;
    if (error != NULL) {
        err.error = KeychainError::GenericError;
        err.message = error->message;
        err.code = error->code;
        g_error_free(error);
        return "";
    } else if (raw_passwords == NULL) {
        err.error = KeychainError::NotFound;
        err.message = "Password not found.";
        err.code = -1; // generic non-zero
        return "";
    } else {
        password = raw_passwords;
    }
    secret_password_free(raw_passwords);
    return password;
}

void deletePassword(const std::string &package, const std::string &service,
                    const std::string &user, Error &err) {
    const auto schema = makeSchema(package);
    GError *error = NULL;

    secret_password_clear_sync(&schema,
                               NULL, // not cancellable
                               &error,
                               ServiceFieldName,
                               service.c_str(),
                               AccountFieldName,
                               user.c_str(),
                               NULL);

    if (error != NULL) {
        err.error = KeychainError::GenericError;
        err.message = error->message;
        err.code = error->code;
        g_error_free(error);
    }
}

} // namespace keychain
