/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm3.h>

#include <botan/internal/isa_extn.h>
#include <botan/internal/sm3_fn.h>
#include <botan/internal/simd_avx2.h>

namespace Botan {

namespace {

static void dump(const char *s, const uint32_t w[], size_t l) {
  for (size_t i = 0; i != l; ++i) {
    printf("%s[%zu] = %08X\n", s, i, w[i]);
  }
}

static void dump(const char *s, const SIMD_8x32 v) {
  uint32_t v32[8];
  v.store_le(v32);
  dump(s, v32, 8);
}

uint32_t P1T1(uint32_t W13) {
   return rotl<15>(W13) ^ rotl<30>(W13) ^ rotl<6>(W13);
}

inline uint32_t SM3_ER(uint32_t W0, uint32_t W7, uint32_t W13, uint32_t W3,
                       uint32_t W10) {
#if 1
  uint32_t T0 = W0 ^ W7;
  uint32_t P1T0 = T0 ^ rotl<15>(T0) ^ rotl<23>(T0);

  return P1T0 ^ P1T1(W13) ^ rotl<7>(W3) ^ W10;
#else
  uint32_t T = W0 ^ W7 ^ rotl<15>(W13);
  uint32_t P1T = T ^ rotl<15>(T) ^ rotl<23>(T);
  return P1T ^ rotl<7>(W3) ^ W10;
  #endif
}

inline uint32_t SM3_E0(uint32_t W0, uint32_t W7, uint32_t W3,
                       uint32_t W10) {
  uint32_t T0 = W0 ^ W7;
  uint32_t P1T0 = T0 ^ rotl<15>(T0) ^ rotl<23>(T0);
  return P1T0 ^ rotl<7>(W3) ^ W10;
}

inline SIMD_8x32 next_SM3_W(const SIMD_8x32& W0, const SIMD_8x32& W1) {
   std::array<uint32_t, 16 + 16> W{}; // W[17...] are left as zero
   W0.store_le(&W[0]);
   W1.store_le(&W[8]);

   SIMD_8x32 W3 = SIMD_8x32::load_le(&W[3]);
   SIMD_8x32 W7 = SIMD_8x32::load_le(&W[7]);
   SIMD_8x32 W10 = SIMD_8x32::load_le(&W[10]);
   SIMD_8x32 W13 = SIMD_8x32::load_le(&W[13]);

   auto W07 = W0 ^ W7 ^ W13.rotl<15>();
   auto P1_W07 = W07 ^ W07.rotl<15>() ^ W07.rotl<23>();
   auto R = P1_W07 ^ W3.rotl<7>() ^ W10;

   R.store_le(W.data());

   uint32_t T[8];
   auto P1_W0 = R.rotl<15>() ^ R.rotl<30>() ^ R.rotl<6>();
   P1_W0.store_le(T);

   W[3] ^= T[0];
   W[4] ^= T[1];
   W[5] ^= T[2];

   W[6] ^= P1T1(W[3]);
   W[7] ^= P1T1(W[4]);

   W[6] ^= W[0];
   W[7] ^= W[1];

   return SIMD_8x32::load_le(&W[0]);
}

}

BOTAN_FN_ISA_AVX2_BMI2 void SM3::compress_digest_x86_avx2(
   digest_type& digest, std::span<const uint8_t> input, size_t blocks) {

   uint32_t A = digest[0];
   uint32_t B = digest[1];
   uint32_t C = digest[2];
   uint32_t D = digest[3];
   uint32_t E = digest[4];
   uint32_t F = digest[5];
   uint32_t G = digest[6];
   uint32_t H = digest[7];
   std::array<uint32_t, 16> W{};

   BufferSlicer in(input);

   for(size_t i = 0; i != blocks; ++i) {
      const auto block = in.take<block_bytes>();
      load_be(W, block);

      SIMD_8x32 W0 = SIMD_8x32::load_be(&block[0]);
      SIMD_8x32 W1 = SIMD_8x32::load_be(&block[32]);
      // clang-format off

      R1(A, B, C, D, E, F, G, H, 0x79CC4519, W[ 0], W[ 4]);
      R1(D, A, B, C, H, E, F, G, 0xF3988A32, W[ 1], W[ 5]);
      R1(C, D, A, B, G, H, E, F, 0xE7311465, W[ 2], W[ 6]);
      R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W[ 3], W[ 7]);
      R1(A, B, C, D, E, F, G, H, 0x9CC45197, W[ 4], W[ 8]);
      R1(D, A, B, C, H, E, F, G, 0x3988A32F, W[ 5], W[ 9]);
      R1(C, D, A, B, G, H, E, F, 0x7311465E, W[ 6], W[10]);
      R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W[ 7], W[11]);

      W0 = next_SM3_W(W0, W1);
      W0.store_le(&W[0]);

      R1(A, B, C, D, E, F, G, H, 0xCC451979, W[ 8], W[12]);
      R1(D, A, B, C, H, E, F, G, 0x988A32F3, W[ 9], W[13]);
      R1(C, D, A, B, G, H, E, F, 0x311465E7, W[10], W[14]);
      R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W[11], W[15]);
      R1(A, B, C, D, E, F, G, H, 0xC451979C, W[12], W[ 0]);
      R1(D, A, B, C, H, E, F, G, 0x88A32F39, W[13], W[ 1]);
      R1(C, D, A, B, G, H, E, F, 0x11465E73, W[14], W[ 2]);
      R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W[15], W[ 3]);

      W1 = next_SM3_W(W1, W0);
      W1.store_le(&W[8]);

      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 7]);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[11]);

      W0 = next_SM3_W(W0, W1);
      W0.store_le(&W[0]);

      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[15]);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[ 3]);

      W1 = next_SM3_W(W1, W0);
      W1.store_le(&W[8]);

      R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W[ 3], W[ 7]);
      R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W[ 7], W[11]);

      W0 = next_SM3_W(W0, W1);
      W0.store_le(&W[0]);

      R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W[11], W[15]);
      R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W[15], W[ 3]);

      W1 = next_SM3_W(W1, W0);
      W1.store_le(&W[8]);

      R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W[ 0], W[ 4]);
      R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W[ 1], W[ 5]);
      R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W[ 2], W[ 6]);
      R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W[ 3], W[ 7]);
      R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W[ 4], W[ 8]);
      R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W[ 5], W[ 9]);
      R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W[ 6], W[10]);
      R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W[ 7], W[11]);

      W0 = next_SM3_W(W0, W1);
      W0.store_le(&W[0]);

      R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W[ 8], W[12]);
      R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W[ 9], W[13]);
      R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W[10], W[14]);
      R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W[11], W[15]);
      R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W[12], W[ 0]);
      R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W[13], W[ 1]);
      R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W[14], W[ 2]);
      R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W[15], W[ 3]);

      // clang-format on

      A = (digest[0] ^= A);
      B = (digest[1] ^= B);
      C = (digest[2] ^= C);
      D = (digest[3] ^= D);
      E = (digest[4] ^= E);
      F = (digest[5] ^= F);
      G = (digest[6] ^= G);
      H = (digest[7] ^= H);
   }
}

}  // namespace Botan
