/*
* PBKDF
* (C) 1999-2007,2012,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PBKDF_H_
#define BOTAN_PBKDF_H_

#include <botan/symkey.h>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>

/*
* This entire interface is deprecated. Use the interface in pwdhash.h
*/
BOTAN_DEPRECATED_HEADER("pbkdf.h")

namespace Botan {

/**
* Base class for PBKDF (password based key derivation function)
* implementations. Converts a password into a key using a salt
* and iterated hashing to make brute force attacks harder.
*
* Starting in 2.8 this functionality is also offered by PasswordHash.
*
* @warning
* This class will be removed in a future major release. Use PasswordHash
*/
class BOTAN_PUBLIC_API(2, 0) PBKDF /* NOLINT(*-special-member-functions) */ {
   public:
      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      BOTAN_DEPRECATED("Use PasswordHashFamily + PasswordHash")
      static std::unique_ptr<PBKDF> create(std::string_view algo_spec, std::string_view provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      BOTAN_DEPRECATED("Use PasswordHashFamily + PasswordHash")
      static std::unique_ptr<PBKDF> create_or_throw(std::string_view algo_spec, std::string_view provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(std::string_view algo_spec);

      /**
      * @return new instance of this same algorithm
      */
      virtual std::unique_ptr<PBKDF> new_object() const = 0;

      /**
      * @return new instance of this same algorithm
      */
      PBKDF* clone() const { return this->new_object().release(); }

      /**
      * @return name of this PBKDF
      */
      virtual std::string name() const = 0;

      virtual ~PBKDF() = default;

      /**
      * Derive a key from a passphrase for a number of iterations
      * specified by either iterations or if iterations == 0 then
      * running until msec time has elapsed.
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      * @param msec if iterations is zero, then instead the PBKDF is
      *        run until msec milliseconds has passed.
      * @return the number of iterations performed
      */
      virtual size_t pbkdf(uint8_t out[],
                           size_t out_len,
                           std::string_view passphrase,
                           const uint8_t salt[],
                           size_t salt_len,
                           size_t iterations,
                           std::chrono::milliseconds msec) const = 0;

      /**
      * Derive a key from a passphrase for a number of iterations.
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      */
      void pbkdf_iterations(uint8_t out[],
                            size_t out_len,
                            std::string_view passphrase,
                            const uint8_t salt[],
                            size_t salt_len,
                            size_t iterations) const;

      /**
      * Derive a key from a passphrase, running until msec time has elapsed.
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param msec if iterations is zero, then instead the PBKDF is
      *        run until msec milliseconds has passed.
      * @param iterations set to the number iterations executed
      */
      void pbkdf_timed(uint8_t out[],
                       size_t out_len,
                       std::string_view passphrase,
                       const uint8_t salt[],
                       size_t salt_len,
                       std::chrono::milliseconds msec,
                       size_t& iterations) const;

      /**
      * Derive a key from a passphrase for a number of iterations.
      *
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      * @return the derived key
      */
      secure_vector<uint8_t> pbkdf_iterations(
         size_t out_len, std::string_view passphrase, const uint8_t salt[], size_t salt_len, size_t iterations) const;

      /**
      * Derive a key from a passphrase, running until msec time has elapsed.
      *
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param msec if iterations is zero, then instead the PBKDF is
      *        run until msec milliseconds has passed.
      * @param iterations set to the number iterations executed
      * @return the derived key
      */
      secure_vector<uint8_t> pbkdf_timed(size_t out_len,
                                         std::string_view passphrase,
                                         const uint8_t salt[],
                                         size_t salt_len,
                                         std::chrono::milliseconds msec,
                                         size_t& iterations) const;

      // Following kept for compat with 1.10:

      /**
      * Derive a key from a passphrase
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param iterations the number of iterations to use (use 10K or more)
      */
      OctetString derive_key(
         size_t out_len, std::string_view passphrase, const uint8_t salt[], size_t salt_len, size_t iterations) const {
         return OctetString(pbkdf_iterations(out_len, passphrase, salt, salt_len, iterations));
      }

      /**
      * Derive a key from a passphrase
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param iterations the number of iterations to use (use 10K or more)
      */
      template <typename Alloc>
      OctetString derive_key(size_t out_len,
                             std::string_view passphrase,
                             const std::vector<uint8_t, Alloc>& salt,
                             size_t iterations) const {
         return OctetString(pbkdf_iterations(out_len, passphrase, salt.data(), salt.size(), iterations));
      }

      /**
      * Derive a key from a passphrase
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      * @param msec is how long to run the PBKDF
      * @param iterations is set to the number of iterations used
      */
      OctetString derive_key(size_t out_len,
                             std::string_view passphrase,
                             const uint8_t salt[],
                             size_t salt_len,
                             std::chrono::milliseconds msec,
                             size_t& iterations) const {
         return OctetString(pbkdf_timed(out_len, passphrase, salt, salt_len, msec, iterations));
      }

      /**
      * Derive a key from a passphrase using a certain amount of time
      * @param out_len the desired length of the key to produce
      * @param passphrase the password to derive the key from
      * @param salt a randomly chosen salt
      * @param msec is how long to run the PBKDF
      * @param iterations is set to the number of iterations used
      */
      template <typename Alloc>
      OctetString derive_key(size_t out_len,
                             std::string_view passphrase,
                             const std::vector<uint8_t, Alloc>& salt,
                             std::chrono::milliseconds msec,
                             size_t& iterations) const {
         return OctetString(pbkdf_timed(out_len, passphrase, salt.data(), salt.size(), msec, iterations));
      }
};

/*
* Compatibility typedef
*/
typedef PBKDF S2K;

/**
* Password based key derivation function factory method
* @param algo_spec the name of the desired PBKDF algorithm
* @param provider the provider to use
* @return pointer to newly allocated object of that type
*/
BOTAN_DEPRECATED("Use PasswordHashFamily + PasswordHash")
inline PBKDF* get_pbkdf(std::string_view algo_spec, std::string_view provider = "") {
   return PBKDF::create_or_throw(algo_spec, provider).release();
}

BOTAN_DEPRECATED("Use PasswordHashFamily + PasswordHash") inline PBKDF* get_s2k(std::string_view algo_spec) {
   return PBKDF::create_or_throw(algo_spec).release();
}

}  // namespace Botan

#endif
