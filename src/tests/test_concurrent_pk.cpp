/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO) && defined(BOTAN_TARGET_OS_HAS_THREADS)
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/internal/fmt.h>
   #include <future>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO) && defined(BOTAN_TARGET_OS_HAS_THREADS)

/*
* Test that public key operations (signing, verification, encryption,
* decryption, KEM) with a shared key from multiple threads produce
* correct results without data races.
*/

namespace {

constexpr size_t THREADS = 10;

class ConcurrentPkTestCase {
   public:
      ConcurrentPkTestCase(std::string_view pk_algo, std::string_view keygen_params, std::string_view op_params) :
            m_pk_algo(pk_algo), m_keygen_params(keygen_params), m_op_params(op_params) {}

      const std::string& algo_name() const { return m_pk_algo; }

      const std::string& op_params() const { return m_op_params; }

      Test::Result result(const std::string_view operation) const {
         return Test::Result(Botan::fmt("Concurrent {} {} {} {}", operation, m_pk_algo, m_keygen_params, m_op_params));
      }

      std::unique_ptr<Botan::Private_Key> try_create_key(Botan::RandomNumberGenerator& rng) const {
         try {
            return Botan::create_private_key(m_pk_algo, rng, m_keygen_params);
         } catch(Botan::Lookup_Error&) {
            return nullptr;
         } catch(Botan::Not_Implemented&) {
            return nullptr;
         }
      }

   private:
      std::string m_pk_algo;
      std::string m_keygen_params;
      std::string m_op_params;
};

Test::Result test_concurrent_signing(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("signing");

   auto rng = Test::new_rng(result.who());
   auto privkey = tc.try_create_key(*rng);
   if(!privkey) {
      result.test_note("Skipping due to missing algorithm", tc.algo_name());
      return result;
   }

   auto pubkey = privkey->public_key();
   const auto test_message = rng->random_vec(32);

   std::vector<std::future<std::vector<uint8_t>>> futures;
   futures.reserve(THREADS);

   for(size_t i = 0; i < THREADS; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> std::vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_Signer signer(*privkey, *thread_rng, tc.op_params());
         return signer.sign_message(test_message, *thread_rng);
      }));
   }

   Botan::PK_Verifier verifier(*pubkey, tc.op_params());

   size_t verified = 0;
   for(size_t i = 0; i < THREADS; ++i) {
      try {
         auto signature = futures[i].get();

         if(signature.empty()) {
            result.test_failure(Botan::fmt("Thread {} produced empty signature", i));
            continue;
         }

         const bool valid = verifier.verify_message(test_message, signature);
         result.test_is_true(Botan::fmt("Thread {} signature is valid", i), valid);
         if(valid) {
            ++verified;
         }
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} failed: {}", i, e.what()));
      }
   }

   result.test_sz_eq("All threads produced verifiable signatures", verified, THREADS);

   return result;
}

Test::Result test_concurrent_verification(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("verification");

   auto rng = Test::new_rng(result.who());
   auto privkey = tc.try_create_key(*rng);
   if(!privkey) {
      result.test_note("Skipping due to missing algorithm");
      return result;
   }

   auto pubkey = privkey->public_key();
   const auto test_message = rng->random_vec(32);

   Botan::PK_Signer signer(*privkey, *rng, tc.op_params());
   const auto signature = signer.sign_message(test_message, *rng);

   std::vector<std::future<bool>> futures;
   futures.reserve(THREADS);

   for(size_t i = 0; i < THREADS; ++i) {
      futures.push_back(std::async(std::launch::async, [&]() -> bool {
         Botan::PK_Verifier verifier(*pubkey, tc.op_params());
         return verifier.verify_message(test_message, signature);
      }));
   }

   for(size_t i = 0; i < THREADS; ++i) {
      try {
         const bool valid = futures[i].get();
         result.test_is_true(Botan::fmt("Thread {} verification succeeded", i), valid);
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_encryption(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("encryption");

   auto rng = Test::new_rng(result.who());
   auto privkey = tc.try_create_key(*rng);
   if(!privkey) {
      result.test_note("Skipping due to missing algorithm", tc.algo_name());
      return result;
   }

   auto pubkey = privkey->public_key();
   const auto test_message = rng->random_vec(32);

   std::vector<std::future<std::vector<uint8_t>>> futures;
   futures.reserve(THREADS);

   for(size_t i = 0; i < THREADS; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> std::vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_Encryptor_EME encryptor(*pubkey, *thread_rng, tc.op_params());
         return encryptor.encrypt(test_message, *thread_rng);
      }));
   }

   Botan::PK_Decryptor_EME decryptor(*privkey, *rng, tc.op_params());

   for(size_t i = 0; i < THREADS; ++i) {
      try {
         auto ciphertext = futures[i].get();
         const auto plaintext = decryptor.decrypt(ciphertext);
         result.test_bin_eq(Botan::fmt("Thread {} decrypts correctly", i), plaintext, test_message);
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} encrypt threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_decryption(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("decryption");

   auto rng = Test::new_rng(result.who());
   auto privkey = tc.try_create_key(*rng);
   if(!privkey) {
      result.test_note("Skipping due to missing algorithm");
      return result;
   }

   auto pubkey = privkey->public_key();
   const auto test_message = rng->random_vec(32);

   Botan::PK_Encryptor_EME encryptor(*pubkey, *rng, tc.op_params());
   const auto ciphertext = encryptor.encrypt(test_message, *rng);

   std::vector<std::future<Botan::secure_vector<uint8_t>>> futures;
   futures.reserve(THREADS);

   for(size_t i = 0; i < THREADS; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> Botan::secure_vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_Decryptor_EME decryptor(*privkey, *thread_rng, tc.op_params());
         return decryptor.decrypt(ciphertext);
      }));
   }

   for(size_t i = 0; i < THREADS; ++i) {
      try {
         auto plaintext = futures[i].get();
         result.test_bin_eq(Botan::fmt("Thread {} decrypts correctly", i), plaintext, test_message);
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} decrypt threw: {}", i, e.what()));
      }
   }

   return result;
}

struct KemEncapResult {
      std::vector<uint8_t> encapsulated_key;
      Botan::secure_vector<uint8_t> shared_key;
};

Test::Result test_concurrent_kem_encap(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("KEM encapsulate");

   auto rng = Test::new_rng(result.who());
   auto privkey = tc.try_create_key(*rng);
   if(!privkey) {
      result.test_note("Skipping due to missing algorithm", tc.algo_name());
      return result;
   }

   auto pubkey = privkey->public_key();

   std::vector<std::future<KemEncapResult>> futures;
   futures.reserve(THREADS);

   for(size_t i = 0; i < THREADS; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> KemEncapResult {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_KEM_Encryptor encryptor(*pubkey, tc.op_params());
         auto kem_enc = encryptor.encrypt(*thread_rng);

         KemEncapResult kr;
         kr.encapsulated_key.assign(kem_enc.encapsulated_shared_key().begin(),
                                    kem_enc.encapsulated_shared_key().end());
         kr.shared_key.assign(kem_enc.shared_key().begin(), kem_enc.shared_key().end());
         return kr;
      }));
   }

   Botan::PK_KEM_Decryptor decryptor(*privkey, *rng, tc.op_params());

   for(size_t i = 0; i < THREADS; ++i) {
      try {
         auto kr = futures[i].get();
         const auto shared_key = decryptor.decrypt(kr.encapsulated_key, 32);
         result.test_bin_eq(Botan::fmt("Thread {} shared key matches", i), shared_key, kr.shared_key);
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} encapsulate threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_kem_decap(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("KEM decapsulate");

   auto rng = Test::new_rng(result.who());
   auto privkey = tc.try_create_key(*rng);
   if(!privkey) {
      result.test_note("Skipping due to missing algorithm");
      return result;
   }

   auto pubkey = privkey->public_key();

   Botan::PK_KEM_Encryptor encryptor(*pubkey, tc.op_params());
   auto kem_enc = encryptor.encrypt(*rng);

   std::vector<std::future<Botan::secure_vector<uint8_t>>> futures;
   futures.reserve(THREADS);

   for(size_t i = 0; i < THREADS; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> Botan::secure_vector<uint8_t> {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_KEM_Decryptor decryptor(*privkey, *thread_rng, tc.op_params());
         return decryptor.decrypt(kem_enc.encapsulated_shared_key(), 0);
      }));
   }

   for(size_t i = 0; i < THREADS; ++i) {
      try {
         auto shared_key = futures[i].get();
         result.test_bin_eq(Botan::fmt("Thread {} shared key matches", i), shared_key, kem_enc.shared_key());
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} decapsulate threw: {}", i, e.what()));
      }
   }

   return result;
}

Test::Result test_concurrent_key_agreement(const ConcurrentPkTestCase& tc) {
   auto result = tc.result("key agreement");

   auto rng = Test::new_rng(result.who());
   auto our_key = tc.try_create_key(*rng);
   if(!our_key) {
      result.test_note("Skipping due to missing algorithm");
      return result;
   }

   auto peer_key = tc.try_create_key(*rng);

   auto* our_ka_key = dynamic_cast<Botan::PK_Key_Agreement_Key*>(our_key.get());
   auto* peer_ka_key = dynamic_cast<Botan::PK_Key_Agreement_Key*>(peer_key.get());
   if(our_ka_key == nullptr || peer_ka_key == nullptr) {
      result.test_failure("Key does not support key agreement");
      return result;
   }

   const auto peer_public = peer_ka_key->public_value();

   // Compute reference shared secret single-threaded
   Botan::PK_Key_Agreement ref_ka(*our_key, *rng, tc.op_params());
   const auto reference_secret = ref_ka.derive_key(32, peer_public);

   std::vector<std::future<Botan::SymmetricKey>> futures;
   futures.reserve(THREADS);

   for(size_t i = 0; i < THREADS; ++i) {
      futures.push_back(std::async(std::launch::async, [&, i]() -> Botan::SymmetricKey {
         auto thread_rng = Test::new_rng(Botan::fmt("{} thread {}", result.who(), i));
         Botan::PK_Key_Agreement ka(*our_key, *thread_rng, tc.op_params());
         return ka.derive_key(32, peer_public);
      }));
   }

   for(size_t i = 0; i < THREADS; ++i) {
      try {
         auto shared_secret = futures[i].get();
         result.test_bin_eq(
            Botan::fmt("Thread {} shared secret matches", i), shared_secret.bits_of(), reference_secret.bits_of());
      } catch(std::exception& e) {
         result.test_failure(Botan::fmt("Thread {} threw: {}", i, e.what()));
      }
   }

   return result;
}

std::vector<Test::Result> concurrent_signing_and_verification_tests() {
   const std::vector<ConcurrentPkTestCase> test_cases = {
      //ConcurrentPkTestCase("RSA", "1536", "PKCS1v15(SHA-256)"),
      ConcurrentPkTestCase("ECDSA", "secp256r1", "SHA-256"),
      ConcurrentPkTestCase("ECKCDSA", "secp256r1", "SHA-256"),
      ConcurrentPkTestCase("ECGDSA", "secp256r1", "SHA-256"),
      ConcurrentPkTestCase("SM2", "sm2p256v1", "SM3"),
      ConcurrentPkTestCase("Ed25519", "", "Pure"),
      ConcurrentPkTestCase("Ed448", "", "Pure"),
      //ConcurrentPkTestCase("ML-DSA", "ML-DSA-4x4", ""),
      //ConcurrentPkTestCase("Dilithium", "Dilithium-4x4-r3", ""),
      //ConcurrentPkTestCase("SLH-DSA", "SLH-DSA-SHA2-128f", ""),
      //ConcurrentPkTestCase("XMSS", "XMSS-SHA2_10_256", "SHA2_10_256"),
      //ConcurrentPkTestCase("HSS-LMS", "SHA-256,HW(5,8)", ""),
   };

   std::vector<Test::Result> results;
   for(const auto& tc : test_cases) {
      results.push_back(test_concurrent_signing(tc));
      results.push_back(test_concurrent_verification(tc));
   }
   return results;
}

std::vector<Test::Result> concurrent_encryption_tests() {
   const std::vector<ConcurrentPkTestCase> test_cases = {
      ConcurrentPkTestCase("RSA", "1536", "OAEP(SHA-256)"),
      ConcurrentPkTestCase("ElGamal", "modp/ietf/1536", "PKCS1v15"),
   };

   std::vector<Test::Result> results;
   for(const auto& tc : test_cases) {
      results.push_back(test_concurrent_encryption(tc));
      results.push_back(test_concurrent_decryption(tc));
   }
   return results;
}

std::vector<Test::Result> concurrent_kem_tests() {
   const std::vector<ConcurrentPkTestCase> test_cases = {
      ConcurrentPkTestCase("RSA", "1536", "Raw"),
      ConcurrentPkTestCase("ClassicMcEliece", "348864f", "Raw"),
      //ConcurrentPkTestCase("ML-KEM", "ML-KEM-512", "Raw"),
      //ConcurrentPkTestCase("Kyber", "Kyber-512-r3", "Raw"),
      //ConcurrentPkTestCase("FrodoKEM", "FrodoKEM-640-SHAKE", "Raw"),
      //ConcurrentPkTestCase("FrodoKEM", "FrodoKEM-640-AES", "Raw"),
   };

   std::vector<Test::Result> results;
   for(const auto& tc : test_cases) {
      results.push_back(test_concurrent_kem_encap(tc));
      results.push_back(test_concurrent_kem_decap(tc));
   }
   return results;
}

std::vector<Test::Result> concurrent_key_agreement_tests() {
   const std::vector<ConcurrentPkTestCase> test_cases = {
      ConcurrentPkTestCase("DH", "modp/ietf/1536", "Raw"),
      ConcurrentPkTestCase("ECDH", "secp256r1", "Raw"),
      ConcurrentPkTestCase("X25519", "", "Raw"),
      ConcurrentPkTestCase("X448", "", "Raw"),
   };

   std::vector<Test::Result> results;
   results.reserve(test_cases.size());
   for(const auto& tc : test_cases) {
      results.push_back(test_concurrent_key_agreement(tc));
   }
   return results;
}

BOTAN_REGISTER_SERIALIZED_TEST_FN("pk_concurrency", "pk_concurrent_sign", concurrent_signing_and_verification_tests);

BOTAN_REGISTER_SERIALIZED_TEST_FN("pk_concurrency", "pk_concurrent_encrypt", concurrent_encryption_tests);

BOTAN_REGISTER_SERIALIZED_TEST_FN("pk_concurrency", "pk_concurrent_kem", concurrent_kem_tests);

BOTAN_REGISTER_SERIALIZED_TEST_FN("pk_concurrency", "pk_concurrent_ka", concurrent_key_agreement_tests);

}  // namespace

#endif

}  // namespace Botan_Tests
