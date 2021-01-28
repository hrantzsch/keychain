# Keychain

![CI Badge](https://github.com/hrantzsch/keychain/workflows/Build%20and%20test/badge.svg)
[![codecov](https://codecov.io/gh/hrantzsch/keychain/branch/master/graph/badge.svg)](https://codecov.io/gh/hrantzsch/keychain)

Keychain is a thin cross-platform wrapper to access the operating system's credential storage in C++.
Keychain supports getting, adding/replacing, and deleting passwords on macOS, Linux, and Windows.

On macOS the passwords are managed by the Keychain, on Linux they are managed by the Secret Service API/libsecret, and on Windows they are managed by Credential Vault.

## Usage

```cpp
#include <iostream>
#include <string>

#include "keychain.h"

int main() {
    // used to indicate errors
    keychain::Error error{};

    // used to identify the password in the OS credentials storage
    const std::string package = "com.example.keychain-app";
    const std::string service = "usage-example";
    const std::string user = "Admin";

    keychain::setPassword(package, service, user, "hunter2", error);
    if (error) {
        std::cout << error.message << std::endl;
        return 1;
    }

    auto password = keychain::getPassword(package, service, user, error);

    // check for specific kinds of errors
    if (error.type == keychain::ErrorType::NotFound) {
        std::cout << "Password not found." << std::endl;
        return 1;
    } else if (error) {
        std::cout << error.message << std::endl;
        return 1;
    }

    std::cout << "Password: " << password << std::endl;

    keychain::deletePassword(package, service, user, error);
    if (error) {
        std::cout << error.message << std::endl;
        return 1;
    }

    return 0;
}
```

## Installation

### Via Conan

Keychain is available in the [ConanCenter](https://conan.io/center/keychain) package repository.
If you're using Conan, simply add the desired version to your requirements.

### Building It Manually

After cloning the repository:
```
$ mkdir _build
$ cmake . -DBUILD_TESTS=yes -B _build
$ cmake --build _build --target test
# cmake --install _build
```

On Linux, Keychain depends on `libsecret`:
```
Debian/Ubuntu: sudo apt-get install libsecret-1-dev
Red Hat/CentOS/Fedora: sudo yum install libsecret-devel
Arch Linux: sudo pacman -Sy libsecret
```

## Security Considerations and General Remarks

Please read, or pretend to read, the considerations below carefully.

### Cross-Application Visibility

Neither on Windows nor on Linux any measures are taken to prevent other applications (of the same user) from accessing stored credentials.
MacOS associates an access control list with each Keychain item and prompts the user if an application that is not whitelisted tries to access the item.
However, this does not apply if the default Keychain is the iCloud Keychain.

### Automatic Login

All platforms encrypt stored passwords with the user's login credentials or (on Linux) with a specific password for the keyring.
Be aware that users can configure their login session or keyring to be unlocked automatically without requiring a password.
In this case **passwords will be stored unencrypted** in plaintext or in some otherwise recoverable format.

### Roaming on Windows

On Windows, persisted credentials are visible to all logon sessions of this same user on the same computer and to logon sessions for this user on other computers (via the _roaming user profile_).
Windows allows configuration of this behavior, but Keychain currently does not expose this functionality.
Please feel free to open an issue if you require this feature.

### Blocking Function Calls

Keychain uses synchronous functions of the OS APIs and does not provide any utilities to make these calls asynchronous.
As a result, all functions can easily be blocking—potentially indefinitely—for example if the OS prompts the user to unlock their credentials storage.
Please make sure not to call Keychain functions from your UI thread.

### Checking If a Password Exists

Keychain does not offer a `bool passwordExists(...)` function.
You can use `getPassword` and check if it returns a `NotFound` error.
This can be useful if you want to make sure that you don't override existing passwords.

## Credit

Keychain took a lot of inspiration from [atom/node-keytar](https://github.com/atom/node-keytar) and a variation of Keytar in [vslavik/poedit](https://github.com/vslavik/poedit/tree/master/src/keychain).
