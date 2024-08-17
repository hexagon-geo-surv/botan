/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPTIONS_IMPL_H_
#define BOTAN_PK_OPTIONS_IMPL_H_

#include <botan/pk_options.h>
#include <string_view>

namespace Botan {

class Public_Key;

PK_Signature_Options parse_legacy_sig_options(const Public_Key& key, std::string_view params);

/**
* For schemes where the hash function is fixed by the key (XMSS, SLH-DSA, ...)
*
* Accepts the hash option only if it names the hash the key already uses.
*/
void validate_for_hash_based_signature(const PK_Signature_Options& options,
                                       std::string_view algo_name,
                                       std::string_view hash_fn);

/**
* For schemes whose signatures are always deterministic
*
* Any request for a deterministic signature is trivially satisfied, so this
* just examines (and thereby acknowledges) the option.
*/
void acknowledge_always_deterministic(const PK_Signature_Options& options);

}  // namespace Botan

#endif
