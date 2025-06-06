/*
* SM4
* (C) 2017 Ribose Inc
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sm4.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

#if defined(BOTAN_HAS_CPUID)
   #include <botan/internal/cpuid.h>
#endif

namespace Botan {

namespace {

alignas(256) const uint8_t SM4_SBOX[256] = {
   0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A,
   0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF,
   0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62, 0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80,
   0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19,
   0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D,
   0x35, 0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87, 0xD4, 0x00,
   0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2, 0x40,
   0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1, 0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
   0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23,
   0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C,
   0x5B, 0x51, 0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8, 0x0A,
   0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
   0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84, 0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D,
   0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48};

/*
* SM4_SBOX_T[j] == L(SM4_SBOX[j]).
*
* Each entry has the form 0xXXYYZZZZ where ZZ = XX ^ YY; can we take
* advantage of this to create a smaller equivalent table?
*
* Additionally YY differs from SBOX[i] by at most 3 (64x 0, 96x 1, 64x 2, 32x 3)
*/
alignas(256) const uint32_t SM4_SBOX_T[256] = {
   0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x06FDFBFB, 0xFCCF3333, 0x65E28787, 0xC93DF4F4, 0x6BB5DEDE, 0x4E165858,
   0x6EB4DADA, 0x44145050, 0xCAC10B0B, 0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414, 0x872BACAC, 0xFB669D9D,
   0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F, 0x02A8AAAA, 0x54451111, 0x5F134C4C,
   0xBE269898, 0x6D482525, 0x9E841A1A, 0x1E061818, 0xFD9B6666, 0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3,
   0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9, 0xFF33CCCC, 0x04555151, 0x270B2C2C, 0x4F420D0D, 0x59EEB7B7,
   0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989, 0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0x0DABA6A6, 0xEDCA2727, 0x28082020,
   0x48EBA3A3, 0xC1975656, 0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB, 0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC,
   0x3EA49A9A, 0x5B461D1D, 0x1B071C1C, 0x3BA59E9E, 0x0CFFF3F3, 0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
   0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616, 0x734E3D3D, 0x08AAA2A2, 0xC869A1A1,
   0xC76AADAD, 0x85830606, 0x7AB0CACA, 0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E, 0x18FBE3E3, 0x47E8AFAF,
   0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0x0E575959, 0xE99F7676, 0xE135D4D4, 0x661E7878, 0xB4249090, 0x360E3838,
   0x265F7979, 0xEF628D8D, 0x38596161, 0x95D24747, 0x2AA08A8A, 0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC,
   0x05010404, 0xA5218484, 0x9879E1E1, 0x9B851E1E, 0x84D75353, 0x00000000, 0x5E471919, 0x0B565D5D, 0xE39D7E7E,
   0x9FD04F4F, 0xBB279C9C, 0x1A534949, 0x7C4D3131, 0xEE36D8D8, 0x0A020808, 0x7BE49F9F, 0x20A28282, 0xD4C71313,
   0xE8CB2323, 0xE69C7A7A, 0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B, 0x40410101, 0xDBC41F1F, 0xD838E0E0,
   0x61B7D6D6, 0x2FA18E8E, 0x2BF4DFDF, 0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
   0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0, 0x721A6868, 0x01545555, 0x19AFB6B6,
   0xDF914E4E, 0xFA32C8C8, 0xF030C0C0, 0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F, 0x691D7474, 0x2EF5DBDB,
   0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181, 0xC0C30303, 0x8D29A4A4, 0xAF238C8C,
   0x07A9AEAE, 0x390D3434, 0x1F524D4D, 0x764F3939, 0xD36EBDBD, 0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515,
   0xA6DD7B7B, 0x09FEF7F7, 0xB68C3A3A, 0x932FBCBC, 0x0F030C0C, 0x03FCFFFF, 0xC26BA9A9, 0xBA73C9C9, 0xD96CB5B5,
   0xDC6DB1B1, 0x375A6D6D, 0x15504545, 0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777,
   0x4CBEF2F2, 0x837EFDFD, 0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505, 0x631F7C7C, 0x50104040, 0x325B6969,
   0xB8DB6363, 0x220A2828, 0xC5C20707, 0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
   0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797, 0x64B6D2D2, 0x70B2C2C2, 0xAD8B2626,
   0xCD68A5A5, 0xCB955E5E, 0x624B2929, 0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9, 0xF1649595, 0x5DBBE6E6,
   0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212, 0x78186060, 0x30F3C3C3, 0x897CF5F5,
   0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373, 0x794C3535, 0xA0208080, 0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8,
   0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121};

inline uint32_t SM4_T_slow(uint32_t b) {
   const uint32_t t = make_uint32(
      SM4_SBOX[get_byte<0>(b)], SM4_SBOX[get_byte<1>(b)], SM4_SBOX[get_byte<2>(b)], SM4_SBOX[get_byte<3>(b)]);

   // L linear transform
   return t ^ rotl<2>(t) ^ rotl<10>(t) ^ rotl<18>(t) ^ rotl<24>(t);
}

inline uint32_t SM4_T(uint32_t b) {
   return (SM4_SBOX_T[get_byte<0>(b)]) ^ rotr<8>(SM4_SBOX_T[get_byte<1>(b)]) ^ rotr<16>(SM4_SBOX_T[get_byte<2>(b)]) ^
          rotr<24>(SM4_SBOX_T[get_byte<3>(b)]);
}

// Variant of T for key schedule
inline uint32_t SM4_Tp(uint32_t b) {
   const uint32_t t = make_uint32(
      SM4_SBOX[get_byte<0>(b)], SM4_SBOX[get_byte<1>(b)], SM4_SBOX[get_byte<2>(b)], SM4_SBOX[get_byte<3>(b)]);

   // L' linear transform
   return t ^ rotl<13>(t) ^ rotl<23>(t);
}

template <size_t R, typename F>
BOTAN_FORCE_INLINE void SM4_E(
   uint32_t& B0, uint32_t& B1, uint32_t& B2, uint32_t& B3, const secure_vector<uint32_t>& RK, F& f) {
   B0 ^= f(B1 ^ B2 ^ B3 ^ RK[4 * R + 0]);
   B1 ^= f(B2 ^ B3 ^ B0 ^ RK[4 * R + 1]);
   B2 ^= f(B3 ^ B0 ^ B1 ^ RK[4 * R + 2]);
   B3 ^= f(B0 ^ B1 ^ B2 ^ RK[4 * R + 3]);
}

template <size_t R, typename F>
BOTAN_FORCE_INLINE void SM4_E(uint32_t& B0,
                              uint32_t& B1,
                              uint32_t& B2,
                              uint32_t& B3,
                              uint32_t& C0,
                              uint32_t& C1,
                              uint32_t& C2,
                              uint32_t& C3,
                              const secure_vector<uint32_t>& RK,
                              F& f) {
   B0 ^= f(B1 ^ B2 ^ B3 ^ RK[4 * R + 0]);
   C0 ^= f(C1 ^ C2 ^ C3 ^ RK[4 * R + 0]);
   B1 ^= f(B2 ^ B3 ^ B0 ^ RK[4 * R + 1]);
   C1 ^= f(C2 ^ C3 ^ C0 ^ RK[4 * R + 1]);
   B2 ^= f(B3 ^ B0 ^ B1 ^ RK[4 * R + 2]);
   C2 ^= f(C3 ^ C0 ^ C1 ^ RK[4 * R + 2]);
   B3 ^= f(B0 ^ B1 ^ B2 ^ RK[4 * R + 3]);
   C3 ^= f(C0 ^ C1 ^ C2 ^ RK[4 * R + 3]);
}

template <size_t R, typename F>
BOTAN_FORCE_INLINE void SM4_D(
   uint32_t& B0, uint32_t& B1, uint32_t& B2, uint32_t& B3, const secure_vector<uint32_t>& RK, F& f) {
   B0 ^= f(B1 ^ B2 ^ B3 ^ RK[4 * R + 3]);
   B1 ^= f(B2 ^ B3 ^ B0 ^ RK[4 * R + 2]);
   B2 ^= f(B3 ^ B0 ^ B1 ^ RK[4 * R + 1]);
   B3 ^= f(B0 ^ B1 ^ B2 ^ RK[4 * R + 0]);
}

template <size_t R, typename F>
BOTAN_FORCE_INLINE void SM4_D(uint32_t& B0,
                              uint32_t& B1,
                              uint32_t& B2,
                              uint32_t& B3,
                              uint32_t& C0,
                              uint32_t& C1,
                              uint32_t& C2,
                              uint32_t& C3,
                              const secure_vector<uint32_t>& RK,
                              F& f) {
   B0 ^= f(B1 ^ B2 ^ B3 ^ RK[4 * R + 3]);
   C0 ^= f(C1 ^ C2 ^ C3 ^ RK[4 * R + 3]);
   B1 ^= f(B2 ^ B3 ^ B0 ^ RK[4 * R + 2]);
   C1 ^= f(C2 ^ C3 ^ C0 ^ RK[4 * R + 2]);
   B2 ^= f(B3 ^ B0 ^ B1 ^ RK[4 * R + 1]);
   C2 ^= f(C3 ^ C0 ^ C1 ^ RK[4 * R + 1]);
   B3 ^= f(B0 ^ B1 ^ B2 ^ RK[4 * R + 0]);
   C3 ^= f(C0 ^ C1 ^ C2 ^ RK[4 * R + 0]);
}

}  // namespace

/*
* SM4 Encryption
*/
void SM4::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return sm4_armv8_encrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_X86)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return sm4_x86_encrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(CPUID::has(CPUID::Feature::GFNI)) {
      return sm4_gfni_encrypt(in, out, blocks);
   }
#endif

   while(blocks >= 2) {
      uint32_t B0 = load_be<uint32_t>(in, 0);
      uint32_t B1 = load_be<uint32_t>(in, 1);
      uint32_t B2 = load_be<uint32_t>(in, 2);
      uint32_t B3 = load_be<uint32_t>(in, 3);

      uint32_t C0 = load_be<uint32_t>(in, 4);
      uint32_t C1 = load_be<uint32_t>(in, 5);
      uint32_t C2 = load_be<uint32_t>(in, 6);
      uint32_t C3 = load_be<uint32_t>(in, 7);

      SM4_E<0>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T_slow);
      SM4_E<1>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_E<2>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_E<3>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_E<4>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_E<5>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_E<6>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_E<7>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T_slow);

      store_be(out, B3, B2, B1, B0, C3, C2, C1, C0);

      in += 2 * BLOCK_SIZE;
      out += 2 * BLOCK_SIZE;
      blocks -= 2;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint32_t B0 = load_be<uint32_t>(in, 0);
      uint32_t B1 = load_be<uint32_t>(in, 1);
      uint32_t B2 = load_be<uint32_t>(in, 2);
      uint32_t B3 = load_be<uint32_t>(in, 3);

      SM4_E<0>(B0, B1, B2, B3, m_RK, SM4_T_slow);
      SM4_E<1>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_E<2>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_E<3>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_E<4>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_E<5>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_E<6>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_E<7>(B0, B1, B2, B3, m_RK, SM4_T_slow);

      store_be(out, B3, B2, B1, B0);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
   }
}

/*
* SM4 Decryption
*/
void SM4::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return sm4_armv8_decrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_X86)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return sm4_x86_decrypt(in, out, blocks);
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(CPUID::has(CPUID::Feature::GFNI)) {
      return sm4_gfni_decrypt(in, out, blocks);
   }
#endif

   while(blocks >= 2) {
      uint32_t B0 = load_be<uint32_t>(in, 0);
      uint32_t B1 = load_be<uint32_t>(in, 1);
      uint32_t B2 = load_be<uint32_t>(in, 2);
      uint32_t B3 = load_be<uint32_t>(in, 3);

      uint32_t C0 = load_be<uint32_t>(in, 4);
      uint32_t C1 = load_be<uint32_t>(in, 5);
      uint32_t C2 = load_be<uint32_t>(in, 6);
      uint32_t C3 = load_be<uint32_t>(in, 7);

      SM4_D<7>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T_slow);
      SM4_D<6>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_D<5>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_D<4>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_D<3>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_D<2>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_D<1>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T);
      SM4_D<0>(B0, B1, B2, B3, C0, C1, C2, C3, m_RK, SM4_T_slow);

      store_be(out, B3, B2, B1, B0, C3, C2, C1, C0);

      in += 2 * BLOCK_SIZE;
      out += 2 * BLOCK_SIZE;
      blocks -= 2;
   }

   for(size_t i = 0; i != blocks; ++i) {
      uint32_t B0 = load_be<uint32_t>(in, 0);
      uint32_t B1 = load_be<uint32_t>(in, 1);
      uint32_t B2 = load_be<uint32_t>(in, 2);
      uint32_t B3 = load_be<uint32_t>(in, 3);

      SM4_D<7>(B0, B1, B2, B3, m_RK, SM4_T_slow);
      SM4_D<6>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_D<5>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_D<4>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_D<3>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_D<2>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_D<1>(B0, B1, B2, B3, m_RK, SM4_T);
      SM4_D<0>(B0, B1, B2, B3, m_RK, SM4_T_slow);

      store_be(out, B3, B2, B1, B0);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
   }
}

bool SM4::has_keying_material() const {
   return !m_RK.empty();
}

/*
* SM4 Key Schedule
*/
void SM4::key_schedule(std::span<const uint8_t> key) {
   // System parameter or family key
   const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

   const uint32_t CK[32] = {0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD,
                            0xC4CBD2D9, 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81,
                            0x888F969D, 0xA4ABB2B9, 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45,
                            0x4C535A61, 0x686F767D, 0x848B9299, 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
                            0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279};

   secure_vector<uint32_t> K(4);
   K[0] = load_be<uint32_t>(key.data(), 0) ^ FK[0];
   K[1] = load_be<uint32_t>(key.data(), 1) ^ FK[1];
   K[2] = load_be<uint32_t>(key.data(), 2) ^ FK[2];
   K[3] = load_be<uint32_t>(key.data(), 3) ^ FK[3];

   m_RK.resize(32);
   for(size_t i = 0; i != 32; ++i) {
      K[i % 4] ^= SM4_Tp(K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i]);
      m_RK[i] = K[i % 4];
   }
}

void SM4::clear() {
   zap(m_RK);
}

size_t SM4::parallelism() const {
#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has(CPUID::Feature::SM4)) {
      return 4;
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(CPUID::has(CPUID::Feature::GFNI)) {
      return 8;
   }
#endif

   return 1;
}

std::string SM4::provider() const {
#if defined(BOTAN_HAS_SM4_ARMV8)
   if(auto feat = CPUID::check(CPUID::Feature::SM4)) {
      return *feat;
   }
#endif

#if defined(BOTAN_HAS_SM4_GFNI)
   if(auto feat = CPUID::check(CPUID::Feature::GFNI)) {
      return *feat;
   }
#endif

   return "base";
}

}  // namespace Botan
