/*
* Ed25519 field element
* (C) 2017 Ribose Inc
*     2025 Jack Lloyd
*
* Based on the public domain code from SUPERCOP ref10 by
* Peter Schwabe, Daniel J. Bernstein, Niels Duif, Tanja Lange, Bo-Yin Yang
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ED25519_FE_H_
#define BOTAN_ED25519_FE_H_

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ct_utils.h>
#include <array>

namespace Botan {

/**
* An element of the field \\Z/(2^255-19)
*
* An element t, entries t[0]...t[9], represents the integer
* t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
* Bounds on each t[i] vary depending on context.
*/
class FE_25519 {
   public:
      /**
      * Default zero initialization
      */
      constexpr FE_25519() {
         clear_mem(m_fe, 10);
      }

      constexpr static FE_25519 zero() {
         return FE_25519();
      }

      constexpr static FE_25519 one() {
         auto o = FE_25519();
         o.m_fe[0] = 1;
         return o;
      }

      constexpr FE_25519(std::span<int32_t, 10> fe) {
         copy_mem(m_fe, fe.data(), 10);
      }

      constexpr FE_25519(int64_t h0,
                         int64_t h1,
                         int64_t h2,
                         int64_t h3,
                         int64_t h4,
                         int64_t h5,
                         int64_t h6,
                         int64_t h7,
                         int64_t h8,
                         int64_t h9) {
         m_fe[0] = static_cast<int32_t>(h0);
         m_fe[1] = static_cast<int32_t>(h1);
         m_fe[2] = static_cast<int32_t>(h2);
         m_fe[3] = static_cast<int32_t>(h3);
         m_fe[4] = static_cast<int32_t>(h4);
         m_fe[5] = static_cast<int32_t>(h5);
         m_fe[6] = static_cast<int32_t>(h6);
         m_fe[7] = static_cast<int32_t>(h7);
         m_fe[8] = static_cast<int32_t>(h8);
         m_fe[9] = static_cast<int32_t>(h9);
      }

      constexpr FE_25519(const FE_25519& other) = default;
      constexpr FE_25519& operator=(const FE_25519& other) = default;

      constexpr FE_25519(FE_25519&& other) = default;
      constexpr FE_25519& operator=(FE_25519&& other) = default;

      static FE_25519 deserialize(const uint8_t b[32]);

      void to_bytes(uint8_t b[32]) const;

      bool is_zero() const {
         std::array<uint8_t, 32> value;
         this->to_bytes(value.data());
         return CT::all_zeros(value.data(), value.size()).as_bool();
      }

      /*
      return 1 if f is in {1,3,5,...,q-2}
      return 0 if f is in {0,2,4,...,q-1}
      */
      bool is_negative() const {
         // TODO could avoid most of the to_bytes computation here
         uint8_t s[32];
         this->to_bytes(s);
         return s[0] & 1;
      }

      static FE_25519 add(const FE_25519& a, const FE_25519& b) {
         FE_25519 z;
         for(size_t i = 0; i != 10; ++i) {
            z[i] = a[i] + b[i];
         }
         return z;
      }

      static FE_25519 sub(const FE_25519& a, const FE_25519& b) {
         FE_25519 z;
         for(size_t i = 0; i != 10; ++i) {
            z[i] = a[i] - b[i];
         }
         return z;
      }

      static FE_25519 negate(const FE_25519& a) {
         FE_25519 z;
         for(size_t i = 0; i != 10; ++i) {
            z[i] = -a[i];
         }
         return z;
      }

      static FE_25519 mul(const FE_25519& a, const FE_25519& b);
      static FE_25519 sqr_iter(const FE_25519& a, size_t iter);

      static FE_25519 sqr(const FE_25519& a) { return sqr_iter(a, 1); }

      static FE_25519 sqr2(const FE_25519& a);
      static FE_25519 pow_22523(const FE_25519& a);
      static FE_25519 invert(const FE_25519& a);

      // TODO remove
      int32_t operator[](size_t i) const { return m_fe[i]; }

      int32_t& operator[](size_t i) { return m_fe[i]; }

   private:
      int32_t m_fe[10];
};

inline void fe_tobytes(uint8_t* b, const FE_25519& x) {
   x.to_bytes(b);
}

inline int fe_isnonzero(const FE_25519& x) {
   return x.is_zero() ? 0 : 1;
}

inline int fe_isnegative(const FE_25519& x) {
   return x.is_negative();
}

inline void fe_add(FE_25519& x, const FE_25519& a, const FE_25519& b) {
   x = FE_25519::add(a, b);
}

inline void fe_sub(FE_25519& x, const FE_25519& a, const FE_25519& b) {
   x = FE_25519::sub(a, b);
}

inline void fe_neg(FE_25519& x, const FE_25519& z) {
   x = FE_25519::negate(z);
}

inline void fe_mul(FE_25519& x, const FE_25519& a, const FE_25519& b) {
   x = FE_25519::mul(a, b);
}

inline void fe_sq(FE_25519& x, const FE_25519& z) {
   x = FE_25519::sqr(z);
}

inline void fe_sq_iter(FE_25519& x, const FE_25519& z, size_t iter) {
   x = FE_25519::sqr_iter(z, iter);
}

inline void fe_sq2(FE_25519& x, const FE_25519& z) {
   x = FE_25519::sqr2(z);
}

inline void fe_invert(FE_25519& x, const FE_25519& z) {
   x = FE_25519::invert(z);
}

inline void fe_pow22523(FE_25519& x, const FE_25519& y) {
   x = FE_25519::pow_22523(y);
}

}  // namespace Botan

#endif
