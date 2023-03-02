/*
* (C) 2017 Ribose Inc
*     2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_NIST_KEYWRAP)
   #include <botan/block_cipher.h>
   #include <botan/nist_keywrap.h>
#endif

extern "C" {

using namespace Botan_FFI;

int botan_nist_kw_enc(const char* cipher_algo,
                      const uint8_t key[], size_t key_len,
                      const uint8_t kek[], size_t kek_len,
                      uint8_t wrapped_key[], size_t *wrapped_key_len)
   {
#if defined(BOTAN_HAS_NIST_KEYWRAP)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto bc = Botan::BlockCipher::create_or_throw(cipher_algo);
      bc->set_key(kek, kek_len);
      const auto output = Botan::nist_key_wrap(key, key_len, *bc);
      return write_vec_output(wrapped_key, wrapped_key_len, output);
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_nist_kw_dec(const char* cipher_algo,
                      const uint8_t wrapped_key[], size_t wrapped_key_len,
                      const uint8_t kek[], size_t kek_len,
                      uint8_t key[], size_t *key_len)
   {
#if defined(BOTAN_HAS_NIST_KEYWRAP)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto bc = Botan::BlockCipher::create_or_throw(cipher_algo);
      bc->set_key(kek, kek_len);
      const auto output = Botan::nist_key_unwrap(wrapped_key, wrapped_key_len, *bc);
      return write_vec_output(key, key_len, output);
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_nist_kwp_enc(const char* cipher_algo,
                       const uint8_t key[], size_t key_len,
                       const uint8_t kek[], size_t kek_len,
                       uint8_t wrapped_key[], size_t *wrapped_key_len)
   {
#if defined(BOTAN_HAS_NIST_KEYWRAP)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto bc = Botan::BlockCipher::create_or_throw(cipher_algo);
      bc->set_key(kek, kek_len);
      const auto output = Botan::nist_key_wrap_padded(key, key_len, *bc);
      return write_vec_output(wrapped_key, wrapped_key_len, output);
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }

int botan_nist_kwp_dec(const char* cipher_algo,
                       const uint8_t wrapped_key[], size_t wrapped_key_len,
                       const uint8_t kek[], size_t kek_len,
                       uint8_t key[], size_t *key_len)
   {
#if defined(BOTAN_HAS_NIST_KEYWRAP)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto bc = Botan::BlockCipher::create_or_throw(cipher_algo);
      bc->set_key(kek, kek_len);
      const auto output = Botan::nist_key_unwrap_padded(wrapped_key, wrapped_key_len, *bc);
      return write_vec_output(key, key_len, output);
      });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
   }


int botan_key_wrap3394(const uint8_t key[], size_t key_len,
                       const uint8_t kek[], size_t kek_len,
                       uint8_t wrapped_key[], size_t* wrapped_key_len)
   {
   std::string cipher_name = "AES-" + std::to_string(8*kek_len);

   return botan_nist_kw_enc(cipher_name.c_str(),
                            key, key_len,
                            kek, kek_len,
                            wrapped_key, wrapped_key_len);
   }

int botan_key_unwrap3394(const uint8_t wrapped_key[], size_t wrapped_key_len,
                         const uint8_t kek[], size_t kek_len,
                         uint8_t key[], size_t* key_len)
   {
   std::string cipher_name = "AES-" + std::to_string(8*kek_len);

   return botan_nist_kw_dec(cipher_name.c_str(),
                            wrapped_key, wrapped_key_len,
                            kek, kek_len,
                            key, key_len);
   }

}
