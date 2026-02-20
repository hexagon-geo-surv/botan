/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/dilithium_shake_xof.h>

namespace Botan {

DilithiumShakeXOF::~DilithiumShakeXOF() = default;

//static
std::unique_ptr<Botan::XOF> DilithiumShakeXOF::createXOF(std::string_view name,
                                                         std::span<const uint8_t> seed,
                                                         uint16_t nonce) {
   auto xof = Botan::XOF::create_or_throw(name);
   const uint8_t nonce8[2] = {static_cast<uint8_t>(nonce), static_cast<uint8_t>(nonce >> 8)};
   xof->update(seed);
   xof->update(nonce8);
   return xof;
}

}  // namespace Botan
