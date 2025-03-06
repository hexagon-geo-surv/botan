/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sha2_32.h>

#include <botan/internal/bit_ops.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>
#include <botan/internal/sha2_32_f.h>
#include <botan/internal/stl_util.h>

namespace Botan {

/*
Your eyes do not decieve you; this is currently just a copy of the
baseline SHA-256 implementation. Because we compile it with BMI2
flags, GCC and Clang use the BMI2 instructions without further help.

Likely instruction scheduling could be improved by using inline asm.
*/
void SHA_256::compress_digest_x86_bmi2(digest_type& digest, std::span<const uint8_t> input, size_t blocks) {
   alignas(64) const uint32_t RC[64] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
      0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
      0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
      0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
      0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
      0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
      0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
      0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

   uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3], E = digest[4], F = digest[5], G = digest[6],
            H = digest[7];

   alignas(64) uint32_t W0[64 * 2];

   BufferSlicer in(input);

   while(blocks >= 2) {
      load_be(std::span{W0, 16}, in.take<block_bytes>());
      load_be(std::span{W0 + 64, 16}, in.take<block_bytes>());

      for(size_t i = 16; i != 64; ++i) {
         W0[i] = W0[i - 16] + sigma<7, 18, 3>(W0[i - 15]) + W0[i - 7] + sigma<17, 19, 10>(W0[i - 2]);
         W0[64+i] = W0[64+i - 16] + sigma<7, 18, 3>(W0[64+i - 15]) + W0[64+i - 7] + sigma<17, 19, 10>(W0[64+i - 2]);
      }

      for(size_t i = 0; i != 64; ++i) {
         W0[i] = W0[i] + RC[i];
         W0[64+i] = W0[64+i] + RC[i];
      }

      for(size_t b = 0; b != 2; ++b) {
         for(size_t r = 0; r != 64; r += 8) {
            SHA2_32_F(A, B, C, D, E, F, G, H, W0[64*b+r+0]);
            SHA2_32_F(H, A, B, C, D, E, F, G, W0[64*b+r+1]);
            SHA2_32_F(G, H, A, B, C, D, E, F, W0[64*b+r+2]);
            SHA2_32_F(F, G, H, A, B, C, D, E, W0[64*b+r+3]);
            SHA2_32_F(E, F, G, H, A, B, C, D, W0[64*b+r+4]);
            SHA2_32_F(D, E, F, G, H, A, B, C, W0[64*b+r+5]);
            SHA2_32_F(C, D, E, F, G, H, A, B, W0[64*b+r+6]);
            SHA2_32_F(B, C, D, E, F, G, H, A, W0[64*b+r+7]);
         }

         A = (digest[0] += A);
         B = (digest[1] += B);
         C = (digest[2] += C);
         D = (digest[3] += D);
         E = (digest[4] += E);
         F = (digest[5] += F);
         G = (digest[6] += G);
         H = (digest[7] += H);
      }

      blocks -= 2;
   }

   if(blocks > 0) {
      load_be(std::span{W0, 16}, in.take<block_bytes>());

      for(size_t i = 16; i != 64; ++i) {
         const uint32_t sigma0_15 = sigma<7, 18, 3>(W0[i - 15]);
         const uint32_t sigma1_2 = sigma<17, 19, 10>(W0[i - 2]);
         W0[i] = W0[i - 16] + sigma0_15 + W0[i - 7] + sigma1_2;
      }

      for(size_t i = 0; i != 64; ++i) {
         W0[i] = W0[i] + RC[i];
      }
      // clang-format off

      for(size_t r = 0; r != 64; r += 8) {
         SHA2_32_F(A, B, C, D, E, F, G, H, W0[r+0]);
         SHA2_32_F(H, A, B, C, D, E, F, G, W0[r+1]);
         SHA2_32_F(G, H, A, B, C, D, E, F, W0[r+2]);
         SHA2_32_F(F, G, H, A, B, C, D, E, W0[r+3]);
         SHA2_32_F(E, F, G, H, A, B, C, D, W0[r+4]);
         SHA2_32_F(D, E, F, G, H, A, B, C, W0[r+5]);
         SHA2_32_F(C, D, E, F, G, H, A, B, W0[r+6]);
         SHA2_32_F(B, C, D, E, F, G, H, A, W0[r+7]);
      }

      // clang-format on

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
      F = (digest[5] += F);
      G = (digest[6] += G);
      H = (digest[7] += H);
   }
}

}  // namespace Botan
