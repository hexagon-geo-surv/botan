/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

   #include <botan/pk_algs.h>
   #include <botan/pk_options.h>
   #include <botan/pubkey.h>
   #include <botan/internal/fmt.h>
   #include <algorithm>
   #include <optional>
   #include <sstream>

namespace Botan_Tests {

namespace {

std::string_view strip_ws(std::string_view s) {
   while(!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
      s.remove_prefix(1);
   }
   while(!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
      s.remove_suffix(1);
   }
   return s;
}

struct AlgoTestConfig {
      std::string algo_name;
      std::string key_params;
      std::string hash;
      std::string padding;
      std::vector<std::pair<std::string, bool>> option_support;
};

/*
* Every option which can be set on a PK_Signature_Options
*
* Each algorithm section in the data file must either use an option in its
* baseline (Hash/Padding) or state via Supports<Option> whether it is accepted.
* This way adding a new option without deciding its status for every algorithm
* fails the test, rather than the option being silently ignored somewhere.
*/
const std::vector<std::string> ALL_OPTIONS = {
   "Hash", "Padding", "Prehash", "Context", "DER", "SaltSize", "Deterministic", "ExplicitTrailer"};

bool has_expectation_for(const AlgoTestConfig& config, std::string_view option) {
   if(option == "Hash" && !config.hash.empty()) {
      return true;
   }
   if(option == "Padding" && !config.padding.empty()) {
      return true;
   }
   for(const auto& [name, supported] : config.option_support) {
      if(name == option) {
         return true;
      }
   }
   return false;
}

std::vector<AlgoTestConfig> parse_sig_options_vec(const std::string& contents) {
   std::vector<AlgoTestConfig> configs;
   AlgoTestConfig* current = nullptr;

   std::istringstream iss(contents);
   std::string line;

   while(std::getline(iss, line)) {
      // Strip inline comments
      if(auto pos = line.find('#'); pos != std::string::npos) {
         line.erase(pos);
      }

      const auto sv = strip_ws(line);
      if(sv.empty()) {
         continue;
      }

      if(sv.front() == '[' && sv.back() == ']') {
         configs.emplace_back();
         current = &configs.back();
         current->algo_name = std::string(sv.substr(1, sv.size() - 2));
         continue;
      }

      if(current == nullptr) {
         throw Test_Error("Key-value pair outside of section");
      }

      const auto eq = sv.find('=');
      if(eq == std::string_view::npos) {
         throw Test_Error(std::string("Line missing '=': ") + std::string(sv));
      }

      const auto key = strip_ws(sv.substr(0, eq));
      const auto value = strip_ws(sv.substr(eq + 1));

      if(key == "KeyParams") {
         current->key_params = std::string(value);
      } else if(key == "Hash") {
         current->hash = std::string(value);
      } else if(key == "Padding") {
         current->padding = std::string(value);
      } else if(key.starts_with("Supports")) {
         const auto opt_name = key.substr(8);  // strip "Supports" prefix
         if(std::find(ALL_OPTIONS.begin(), ALL_OPTIONS.end(), opt_name) == ALL_OPTIONS.end()) {
            throw Test_Error(std::string("Unknown option: '") + std::string(opt_name) + "'");
         }
         bool supported = false;
         if(value == "true") {
            supported = true;
         } else if(value == "false") {
            supported = false;
         } else {
            throw Test_Error(std::string("Invalid boolean: '") + std::string(value) + "'");
         }
         current->option_support.emplace_back(std::string(opt_name), supported);
      } else {
         throw Test_Error(std::string("Unknown key: '") + std::string(key) + "'");
      }
   }

   for(const auto& config : configs) {
      for(const auto& option : ALL_OPTIONS) {
         if(!has_expectation_for(config, option)) {
            throw Test_Error(Botan::fmt("[{}] does not state if option {} is supported", config.algo_name, option));
         }
      }
   }

   return configs;
}

Botan::PK_Signature_Options make_baseline(const AlgoTestConfig& config) {
   Botan::PK_Signature_Options opts;
   if(!config.hash.empty()) {
      opts = opts.with_hash(config.hash);
   }
   if(!config.padding.empty()) {
      opts = opts.with_padding(config.padding);
   }
   return opts;
}

Botan::PK_Signature_Options with_added_option(Botan::PK_Signature_Options baseline, std::string_view option) {
   if(option == "Padding") {
      return baseline.with_padding("PKCS1v15");
   }
   if(option == "Prehash") {
      return baseline.with_prehash();
   }
   if(option == "Context") {
      return baseline.with_context("test context");
   }
   if(option == "DER") {
      return baseline.with_der_encoded_signature();
   }
   if(option == "SaltSize") {
      return baseline.with_salt_size(32);
   }
   if(option == "Deterministic") {
      return baseline.with_deterministic_signature();
   }
   if(option == "ExplicitTrailer") {
      return baseline.with_explicit_trailer_field();
   }
   if(option == "Hash") {
      return baseline.with_hash("SHA-256");
   }
   throw Test_Error(std::string("Unknown option name: '") + std::string(option) + "'");
}

/*
* Verifier options which conflict with a signature created using the given
* option; verifying with these must fail (or the verifier must refuse them),
* otherwise the option was accepted by the signer but not actually applied.
*/
std::optional<Botan::PK_Signature_Options> conflicting_verifier_options(Botan::PK_Signature_Options baseline,
                                                                        std::string_view option) {
   if(option == "Context") {
      return baseline.with_context("a different context");
   }
   if(option == "SaltSize") {
      return baseline.with_salt_size(16);
   }
   if(option == "Prehash" || option == "DER" || option == "ExplicitTrailer") {
      // The baseline itself does not use the option
      return baseline;
   }
   return std::nullopt;
}

class PK_Signature_Options_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         const auto file_contents = Test::read_data_file("pubkey/pk_sig_options.vec");
         const auto configs = parse_sig_options_vec(file_contents);

         std::vector<Test::Result> results;

         for(const auto& config : configs) {
            Test::Result result("PK_Sig_Options " + config.algo_name);
            result.start_timer();

            std::unique_ptr<Botan::Private_Key> key;
            try {
               // For entries like "RSA/PSS", use just "RSA" for key generation
               auto key_algo = config.algo_name;
               if(auto slash = key_algo.find('/'); slash != std::string::npos) {
                  key_algo = key_algo.substr(0, slash);
               }
               key = Botan::create_private_key(key_algo, rng(), config.key_params);
            } catch(const Botan::Lookup_Error&) {
               result.test_note("Skipping - algorithm not available");
               result.end_timer();
               results.push_back(std::move(result));
               continue;
            }

            if(!key) {
               result.test_note("Key generation unavailable");
               result.end_timer();
               results.push_back(std::move(result));
               continue;
            }

            const auto pub = key->public_key();

            // Test that the baseline options produce valid signatures
            test_baseline(result, *key, *pub, config);

            // Test each option individually
            for(const auto& [opt_name, supported] : config.option_support) {
               if(supported) {
                  test_option_accepted(result, *key, *pub, config, opt_name);
               } else {
                  test_option_rejected(result, *key, *pub, config, opt_name);
               }
            }

            result.end_timer();
            results.push_back(std::move(result));
         }

         return results;
      }

   private:
      void test_baseline(Test::Result& result,
                         const Botan::Private_Key& key,
                         const Botan::Public_Key& pub,
                         const AlgoTestConfig& config) {
         result.test_no_throw("Baseline signer creation", [&] {
            const auto opts = make_baseline(config);
            Botan::PK_Signer signer(key, rng(), opts);
            Botan::PK_Verifier verifier(pub, make_baseline(config));

            const std::vector<uint8_t> message = {0x61, 0x62, 0x63, 0x64};
            auto sig = signer.sign_message(message, rng());
            result.test_is_true("Baseline sign/verify", verifier.verify_message(message, sig));
         });
      }

      void test_option_accepted(Test::Result& result,
                                const Botan::Private_Key& key,
                                const Botan::Public_Key& pub,
                                const AlgoTestConfig& config,
                                const std::string& opt_name) {
         result.test_no_throw(opt_name + " accepted", [&] {
            const auto opts = with_added_option(make_baseline(config), opt_name);
            Botan::PK_Signer signer(key, rng(), opts);
            Botan::PK_Verifier verifier(pub, with_added_option(make_baseline(config), opt_name));

            const std::vector<uint8_t> message = {0x61, 0x62, 0x63, 0x64};
            auto sig = signer.sign_message(message, rng());
            result.test_is_true(opt_name + " sign/verify", verifier.verify_message(message, sig));

            // Now check that the option actually took effect
            if(opt_name == "Deterministic") {
               // Stateful schemes never produce the same signature twice
               if(!key.stateful_operation()) {
                  auto sig2 = signer.sign_message(message, rng());
                  result.test_bin_eq("Deterministic signatures are identical", sig, sig2);
               }
            } else if(auto conflicting = conflicting_verifier_options(make_baseline(config), opt_name)) {
               bool rejected = false;
               try {
                  Botan::PK_Verifier other_verifier(pub, *conflicting);
                  rejected = !other_verifier.verify_message(message, sig);
               } catch(Botan::Exception&) {
                  rejected = true;
               }
               result.test_is_true(opt_name + " is applied (conflicting verifier rejects)", rejected);
            }
         });
      }

      void test_option_rejected(Test::Result& result,
                                const Botan::Private_Key& key,
                                const Botan::Public_Key& pub,
                                const AlgoTestConfig& config,
                                const std::string& opt_name) {
         const auto opts = with_added_option(make_baseline(config), opt_name);

         result.test_throws(opt_name + " rejected by signer", [&] { Botan::PK_Signer(key, rng(), opts); });

         // Deterministic is a signing-only option; verifiers don't check it
         if(opt_name == "Deterministic") {
            return;
         }

         result.test_throws(opt_name + " rejected by verifier", [&] { Botan::PK_Verifier(pub, opts); });
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options", PK_Signature_Options_Test);

   #if defined(BOTAN_HAS_ED25519)

/*
* An option which no part of the signature scheme examines must be rejected,
* naming the offending option, without any scheme specific code.
*/
class PK_Signature_Options_Unexamined_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_Signature_Options rejects unexamined options");

         auto key = Botan::create_private_key("Ed25519", rng());
         if(!key) {
            result.test_note("Skipping - Ed25519 not available");
            return {result};
         }
         const auto pub = key->public_key();

         const auto opts = Botan::PK_Signature_Options().with_salt_size(32).with_explicit_trailer_field();

         auto check_message = [&](const std::string& what, const std::exception& e) {
            const std::string msg = e.what();
            result.test_is_true(what + " names the unexamined options",
                                msg.find("Ed25519 does not support the signature option(s): salt size, explicit "
                                         "trailer field") != std::string::npos);
         };

         try {
            Botan::PK_Signer signer(*key, rng(), opts);
            result.test_failure("PK_Signer accepted unexamined options");
         } catch(Botan::Invalid_Argument& e) {
            check_message("PK_Signer", e);
         }

         try {
            Botan::PK_Verifier verifier(*pub, opts);
            result.test_failure("PK_Verifier accepted unexamined options");
         } catch(Botan::Invalid_Argument& e) {
            check_message("PK_Verifier", e);
         }

         // The deterministic option is only meaningful for signing; verifiers accept it
         result.test_no_throw("Verifier ignores deterministic option", [&] {
            Botan::PK_Verifier verifier(*pub, Botan::PK_Signature_Options().with_deterministic_signature());
         });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options_unexamined", PK_Signature_Options_Unexamined_Test);

   #endif

   #if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EMSA_PKCS1) && defined(BOTAN_HAS_EMSA_RAW) && defined(BOTAN_HAS_PSS)

/*
* RSA must never fall back to raw or hashless signing when options are missing
*/
class PK_Signature_Options_RSA_Explicit_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_Signature_Options RSA requires explicit padding");

         auto key = Botan::create_private_key("RSA", rng(), "1024");
         if(!key) {
            result.test_note("Skipping - RSA not available");
            return {result};
         }
         const auto pub = key->public_key();

         auto rejected = [&](const std::string& what, const Botan::PK_Signature_Options& opts) {
            result.test_throws(what + " rejected by signer", [&] { Botan::PK_Signer(*key, rng(), opts); });
            result.test_throws(what + " rejected by verifier", [&] { Botan::PK_Verifier(*pub, opts); });
         };

         rejected("No options", Botan::PK_Signature_Options());
         rejected("Hash without padding", Botan::PK_Signature_Options().with_hash("SHA-256"));
         rejected("PKCS1v15 without hash", Botan::PK_Signature_Options().with_padding("PKCS1v15"));
         rejected("PSS without hash", Botan::PK_Signature_Options().with_padding("PSS"));
         rejected("Raw with unknown prehash",
                  Botan::PK_Signature_Options().with_padding("Raw").with_prehash("NoSuchHash"));
         rejected("Raw with unnamed prehash", Botan::PK_Signature_Options().with_padding("Raw").with_prehash());
         rejected("PKCS1v15 raw with unnamed prehash",
                  Botan::PK_Signature_Options().with_padding("PKCS1v15").with_hash("Raw").with_prehash());

         // Raw signing is still available, but only when asked for explicitly
         result.test_no_throw("Explicit raw padding accepted", [&] {
            Botan::PK_Signer signer(*key, rng(), Botan::PK_Signature_Options().with_padding("Raw"));
            Botan::PK_Verifier verifier(*pub, Botan::PK_Signature_Options().with_padding("Raw"));
            const std::vector<uint8_t> msg(32, 0x42);
            const auto sig = signer.sign_message(msg, rng());
            result.test_is_true("Raw roundtrip", verifier.verify_message(msg, sig));
         });

         // The deterministic option is ignored for verification, even where the
         // padding scheme would reject it for signing
         auto pss = Botan::PK_Signature_Options().with_padding("PSS").with_hash("SHA-256");
         result.test_throws("PSS with salt cannot be deterministic when signing",
                            [&] { Botan::PK_Signer(*key, rng(), pss.with_deterministic_signature()); });
         result.test_no_throw("Verifier ignores deterministic for PSS", [&] {
            Botan::PK_Signer signer(*key, rng(), pss);
            Botan::PK_Verifier verifier(*pub, pss.with_deterministic_signature());
            const std::vector<uint8_t> msg(32, 0x42);
            const auto sig = signer.sign_message(msg, rng());
            result.test_is_true("PSS roundtrip", verifier.verify_message(msg, sig));
         });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options_rsa_explicit", PK_Signature_Options_RSA_Explicit_Test);

   #endif

}  // namespace

}  // namespace Botan_Tests

#endif
