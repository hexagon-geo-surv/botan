/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm3.h>

namespace Botan {

//static
void SM3::compress_n_x86(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {}

}  // namespace Botan
