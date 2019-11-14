#include <assert.h>

#include <optional>
#include <string>
#include <variant>

namespace keychain {

class Keychain {
   public:
    struct Error {
        std::string message;
    };
    using Success = std::monostate;
    using Password = std::string;
    using Result = std::variant<Success, Password, Error>;

    static Result getPassword(const std::string &service,
                              const std::string &user);
    static Result setPassword(const std::string &service,
                              const std::string &user,
                              const std::string &password);
    static Result deletePassword(const std::string &service,
                                 const std::string &user);

   public:
    /*! \brief Construct a Keychain specific to a service/user combination
     *
     * \param service Identifier for the service whose password should be stored
     *                or updated. Note that a platform specific service name
     *                will be used based on the provided identifier.
     *                \sa getServiceName
     * \param user
     */
    Keychain(const std::string &service, const std::string &user);

    std::optional<std::string> getPassword();
    bool setPassword(const std::string &password);
    bool deletePassword();

    //! Return the error resulting from the most recent call to getPassword,
    //! addPassword, or deletePassword, if any
    std::optional<std::string> lastError();

   private:
    //! \brief Create a platform specific service identifier
    std::string makeServiceName(const std::string &service);

    void clearError();

    template <typename F>
    bool updatePassword(F &&updateFun) {
        clearError();

        Result result = updateFun();

        // should either return a Success or an Error
        assert(!std::holds_alternative<Keychain::Success>(result));

        auto err = std::get_if<Keychain::Error>(&result);
        if (err) _lastError = err->message;
        return !err;
    }

    std::string _service;
    std::string _user;
    std::optional<std::string> _lastError;
};

}  // namespace keychain
