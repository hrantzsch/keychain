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
    /*! \brief Construct a Keychain object
     *
     * \param package Package identifier corresponding to the format
     *                com.example.application. On MacOS this identifier is pre-
     *                pended to the service name and is visible to users. On
     *                Linux it is used as the schema name and is normally not
     *                visible to users. On Windows this parameter is ignored.
     */
    Keychain(const std::string &package);

    /*! \brief Get a password
     *
     * \param service Identifier for the service whose passwords should be
     * stored or updated.
     *
     * \param username Username or account name that the stored or updated
     *                 passwords belong to.
     */
    std::optional<std::string> getPassword(const std::string &service,
                                           const std::string &username);

    /*! \brief Update a password
     *
     * \param password The password to be stored.
     *
     * \param service Identifier for the service whose passwords should be
     * stored or updated.
     *
     * \param username Username or account name that the stored or updated
     *                 passwords belong to.
     */
    bool setPassword(const std::string &password, const std::string &service,
                     const std::string &username);

    /*! \brief Delete a password
     *
     * \param service Identifier for the service whose passwords should be
     * stored or updated.
     *
     * \param username Username or account name that the stored or updated
     *                 passwords belong to.
     */
    bool deletePassword(const std::string &service,
                        const std::string &username);

    /*! \brief Get the last error, if any
     *
     * Return the error resulting from the most recent call to getPassword,
     * addPassword, or deletePassword. If the last call to any of the functions
     * did not result in an error, std::nullopt is returned.
     */
    std::optional<std::string> lastError() const;

   protected:
    void clearError();

    template <typename F>
    bool updatePassword(F &&updateFun);

   protected:
    std::string _package;
    std::optional<std::string> _lastError;
};

/*! \brief Convenience utility for accessing only one specific service and
 *         account in a Keychain.
 */
class Account : public Keychain {
   public:
    /*! \brief Construct a Account specific to a service/username combination
     *
     * \param service Identifier for the service whose passwords should be
     *                stored or updated.
     *
     * \param username Username or account name that the stored or updated
     *                 passwords belong to.
     *
     * \param package Package identifier corresponding to the format
     *                com.example.application. On MacOS this identifier is pre-
     *                pended to the service name and is visible to users. On
     *                Linux it is used as the schema name and is normally not
     *                visible to users. On Windows this parameter is ignored.
     */
    Account(const std::string &package, const std::string &service,
            const std::string &username);

    //! \brief Get the password
    std::optional<std::string> getPassword();
    //! \brief Update the password
    bool setPassword(const std::string &password);
    //! \brief Delete the password
    bool deletePassword();

   protected:
    std::string _service;
    std::string _username;
};

}  // namespace keychain
