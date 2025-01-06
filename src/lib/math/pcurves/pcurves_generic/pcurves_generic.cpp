/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_generic.h>

#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/pcurves_instance.h>
#include <botan/internal/primality.h>

#include <botan/internal/pcurves_util.h>

namespace Botan::PCurve {

typedef const GenericPrimeOrderCurve* GPOC;

class GenericScalar final {
   public:
      typedef word W;
      static constexpr size_t N = PrimeOrderCurve::StorageWords;

      static GenericScalar from_wide_bytes(GPOC curve, std::span<const uint8_t> bytes);

      static std::optional<GenericScalar> deserialize(GPOC curve, std::span<const uint8_t> bytes);

      static GenericScalar from_stash(GPOC curve, const PrimeOrderCurve::Scalar& s) {
         return GenericScalar(curve, s._value());
      }

      static GenericScalar zero(GPOC curve) {
         std::array<W, N> zeros = {};
         return GenericScalar(curve, zeros);
      }

      static GenericScalar one(GPOC curve) {
         return GenericScalar(curve, monty_r1(curve));
      }

      static GenericScalar random(GPOC curve, RandomNumberGenerator& rng) {
         constexpr size_t MAX_ATTEMPTS = 1000;

         const size_t bits = modulus_bits(curve);

         std::vector<uint8_t> buf(modulus_bytes(curve));

         for(size_t i = 0; i != MAX_ATTEMPTS; ++i) {
            rng.randomize(buf);

            // Zero off high bits that if set would certainly cause us
            // to be out of range
            if(bits % 8 != 0) {
               const uint8_t mask = 0xFF >> (8 - (bits % 8));
               buf[0] &= mask;
            }

            if(auto s = GenericScalar::deserialize(curve, buf)) {
               if(s.value().is_nonzero().as_bool()) {
                  return s.value();
               }
            }
         }

         throw Internal_Error("Failed to generate random Scalar within bounded number of attempts");
      }

      friend GenericScalar operator+(const GenericScalar& a, const GenericScalar& b) {
         auto curve = check_curve(a, b);

         std::array<W, N> t;
         W carry = bigint_add<W, N>(t, a.value(), b.value());

         std::array<W, N> r;
         bigint_monty_maybe_sub<N>(r.data(), carry, t.data(), modulus(curve).data());
         return GenericScalar(curve, r);
      }

      friend GenericScalar operator-(const GenericScalar& a, const GenericScalar& b) { return a + b.negate(); }

      friend GenericScalar operator*(const GenericScalar& a, const GenericScalar& b) {
         auto curve = check_curve(a, b);

         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), a.data(), b.data());
         return GenericScalar(curve, redc(curve, z));
      }

      GenericScalar& operator*=(const GenericScalar& other) {
         auto curve = check_curve(*this, other);

         std::array<W, 2 * N> z;
         comba_mul<N>(z.data(), data(), other.data());
         m_val = redc(curve, z);
         return (*this);
      }

      GenericScalar square() const {
         auto curve = this->m_curve;

         std::array<W, 2 * N> z;
         comba_sqr<N>(z.data(), this->data());
         return GenericScalar(curve, redc(curve, z));
      }

      /// Repeated squaring in place
      void square_n(size_t n) {
         std::array<W, 2 * N> z;
         for(size_t i = 0; i != n; ++i) {
            comba_sqr<N>(z.data(), this->data());
            m_val = redc(m_curve, z);
         }
      }

      GenericScalar pow_vartime(const std::array<W, N>& exp) const {
         constexpr size_t WindowBits = 4;
         constexpr size_t WindowElements = (1 << WindowBits) - 1;

         const size_t Windows = (modulus_bits(m_curve) + WindowBits - 1) / WindowBits;

         /*
         A simple fixed width window modular multiplication.

         TODO: investigate using sliding window here
         */

         std::vector<GenericScalar> tbl;

         tbl.push_back(*this);

         tbl[0] = (*this);

         for(size_t i = 1; i != WindowElements; ++i) {
            if(i % 2 == 1) {
               tbl.push_back(tbl[i / 2].square());
            } else {
               tbl.push_back(tbl[i - 1] * tbl[0]);
            }
         }

         auto r = GenericScalar::one(m_curve);

         const size_t w0 = read_window_bits<WindowBits>(std::span{exp}, (Windows - 1) * WindowBits);

         if(w0 > 0) {
            r = tbl[w0 - 1];
         }

         for(size_t i = 1; i != Windows; ++i) {
            r.square_n(WindowBits);

            const size_t w = read_window_bits<WindowBits>(std::span{exp}, (Windows - i - 1) * WindowBits);

            if(w > 0) {
               r *= tbl[w - 1];
            }
         }

         return r;
      }

      GenericScalar negate() const {
         auto x_is_zero = CT::all_zeros(this->data(), N);

         std::array<W, N> r;
         bigint_sub3(r.data(), modulus(m_curve).data(), N, this->data(), N);
         x_is_zero.if_set_zero_out(r.data(), N);
         return GenericScalar(m_curve, r);
      }

      GenericScalar invert() const {
         return pow_vartime(modulus_minus_2(m_curve));
      }

      void serialize_to(std::span<uint8_t> bytes) const;

      CT::Choice is_zero() const {
         return CT::all_zeros(m_val.data(), N).as_choice();
      }

      CT::Choice is_nonzero() const {
         return !is_zero();
      }

      bool operator==(const GenericScalar& other) const {
         if(this->m_curve != other.m_curve) {
            return false;
         }

         return CT::is_equal(m_val.data(), other.m_val.data(), N).as_bool();
      }

      std::array<W, N> stash_value() const { return m_val; }

   private:
      const std::array<W, N>& value() const { return m_val; }

      constexpr const W* data() const { return m_val.data(); }

      static GPOC check_curve(const GenericScalar& a, const GenericScalar& b) {
         BOTAN_STATE_CHECK(a.m_curve == b.m_curve);
         return a.m_curve;
      }

      static size_t words(GPOC curve) {
         return curve->m_words;
      }

      static std::array<W, N> redc(GPOC curve, std::array<W, 2*N> z) {
         // if constexpr(IsField) ...
         return curve->m_order_monty_r1;
      }

      static const std::array<W, N>& monty_r1(GPOC curve) {
         // if constexpr(IsField) ...
         return curve->m_order_monty_r1;
      }

      static const std::array<W, N>& modulus(GPOC curve) {
         // if constexpr(IsField) ...
         return curve->m_order;
      }

      static size_t modulus_bits(GPOC curve) {
         // if constexpr(IsField) ...
         return curve->m_order_bits;
      }

      static size_t modulus_bytes(GPOC curve) {
         // if constexpr(IsField) ...
         return curve->m_scalar_bytes;
      }

      static const std::array<W, N>& modulus_minus_2(GPOC curve) {
         // if constexpr(IsField) ...
         return curve->m_order_minus_2;
      }

      GenericScalar(GPOC curve, std::array<W, N> val) : m_curve(curve), m_val(val) {}

      GPOC m_curve;
      std::array<W, N> m_val;
};

namespace {

std::array<word, PrimeOrderCurve::StorageWords> bn_to_fixed(const BigInt& n) {
   const size_t n_words = n.sig_words();
   BOTAN_ASSERT_NOMSG(n_words <= PrimeOrderCurve::StorageWords);

   std::array<word, PrimeOrderCurve::StorageWords> r = {};
   copy_mem(r.data(), n._data(), n_words);
   return r;
}

}

GenericPrimeOrderCurve::GenericPrimeOrderCurve(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) :
   m_words(p.sig_words()),
   m_order_bits(order.bits()),
   m_scalar_bytes(order.bytes()),
   m_fe_bytes(p.bytes()),
   m_order(bn_to_fixed(order)) {

   BOTAN_ASSERT_NOMSG(m_scalar_bytes == m_fe_bytes);
   BOTAN_ASSERT_NOMSG(order.sig_words() == m_words);

   // TODO setup Montgomery R1,R2,R3
}

size_t GenericPrimeOrderCurve::order_bits() const {
   return m_order_bits;
}

size_t GenericPrimeOrderCurve::scalar_bytes() const {
   return m_scalar_bytes;
}

size_t GenericPrimeOrderCurve::field_element_bytes() const {
   return m_fe_bytes;
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::mul_by_g(const Scalar& scalar,
                                                                  RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(scalar, rng);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::mul(const AffinePoint& pt,
                                                             const Scalar& scalar,
                                                             RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(pt, scalar, rng);
   throw Not_Implemented(__func__);
}

secure_vector<uint8_t> GenericPrimeOrderCurve::mul_x_only(const AffinePoint& pt,
                                                          const Scalar& scalar,
                                                          RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(pt, scalar, rng);
   throw Not_Implemented(__func__);
}

std::unique_ptr<const PrimeOrderCurve::PrecomputedMul2Table> GenericPrimeOrderCurve::mul2_setup(
   const AffinePoint& x, const AffinePoint& y) const {
   BOTAN_UNUSED(x, y);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::ProjectivePoint> GenericPrimeOrderCurve::mul2_vartime(const PrecomputedMul2Table& tableb,
                                                                                     const Scalar& s1,
                                                                                     const Scalar& s2) const {
   BOTAN_UNUSED(tableb, s1, s2);
   throw Not_Implemented(__func__);
};

std::optional<PrimeOrderCurve::ProjectivePoint> GenericPrimeOrderCurve::mul_px_qy(
   const AffinePoint& p, const Scalar& x, const AffinePoint& q, const Scalar& y, RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(p, x, q, y, rng);
   throw Not_Implemented(__func__);
};

bool GenericPrimeOrderCurve::mul2_vartime_x_mod_order_eq(const PrecomputedMul2Table& tableb,
                                                         const Scalar& v,
                                                         const Scalar& s1,
                                                         const Scalar& s2) const {
   BOTAN_UNUSED(tableb, v, s1, s2);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::base_point_mul_x_mod_order(const Scalar& scalar,
                                                                           RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(scalar, rng);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::generator() const {
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::point_to_affine(const ProjectivePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_to_projective(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_double(const ProjectivePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_add(const ProjectivePoint& a,
                                                                   const ProjectivePoint& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_add_mixed(const ProjectivePoint& a,
                                                                         const AffinePoint& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::point_negate(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

bool GenericPrimeOrderCurve::affine_point_is_identity(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point_compressed(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point_x(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_scalar(std::span<uint8_t> bytes, const Scalar& scalar) const {
   BOTAN_ARG_CHECK(bytes.size() == m_scalar_bytes, "Invalid length to serialize_scalar");
   GenericScalar::from_stash(this, scalar).serialize_to(bytes);
}

std::optional<PrimeOrderCurve::Scalar> GenericPrimeOrderCurve::deserialize_scalar(
   std::span<const uint8_t> bytes) const {

   if(auto s = GenericScalar::deserialize(this, bytes)) {
      return stash(s.value());
   } else {
      return std::nullopt;
   }
}

std::optional<PrimeOrderCurve::Scalar> GenericPrimeOrderCurve::scalar_from_wide_bytes(
   std::span<const uint8_t> bytes) const {

   return stash(GenericScalar::from_wide_bytes(this, bytes));
}

std::optional<PrimeOrderCurve::AffinePoint> GenericPrimeOrderCurve::deserialize_point(
   std::span<const uint8_t> bytes) const {
   BOTAN_UNUSED(bytes);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_add(const Scalar& a, const Scalar& b) const {
   return stash(GenericScalar::from_stash(this, a) + GenericScalar::from_stash(this, b));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_sub(const Scalar& a, const Scalar& b) const {
   return stash(GenericScalar::from_stash(this, a) - GenericScalar::from_stash(this, b));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_mul(const Scalar& a, const Scalar& b) const {
   return stash(GenericScalar::from_stash(this, a) * GenericScalar::from_stash(this, b));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_square(const Scalar& s) const {
      return stash(GenericScalar::from_stash(this, s).square());
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_invert(const Scalar& s) const {
   return stash(GenericScalar::from_stash(this, s).invert());
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_negate(const Scalar& s) const {
   return stash(GenericScalar::from_stash(this, s).negate());
}

bool GenericPrimeOrderCurve::scalar_is_zero(const Scalar& s) const {
   return GenericScalar::from_stash(this, s).is_zero().as_bool();
}

bool GenericPrimeOrderCurve::scalar_equal(const Scalar& a, const Scalar& b) const {
   return GenericScalar::from_stash(this, a) == GenericScalar::from_stash(this, b);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_zero() const {
   return stash(GenericScalar::zero(this));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_one() const {
   return stash(GenericScalar::one(this));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::random_scalar(RandomNumberGenerator& rng) const {
   return stash(GenericScalar::random(this, rng));
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::stash(const GenericScalar& s) const {
   return Scalar::_create(shared_from_this(), s.stash_value());
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::hash_to_curve_nu(std::string_view hash,
                                                                      std::span<const uint8_t> input,
                                                                      std::span<const uint8_t> domain_sep) const {
   BOTAN_UNUSED(hash, input, domain_sep);
   throw Not_Implemented("Hash to curve is not implemented for this curve");
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::hash_to_curve_ro(std::string_view hash,
                                                                          std::span<const uint8_t> input,
                                                                          std::span<const uint8_t> domain_sep) const {
   BOTAN_UNUSED(hash, input, domain_sep);
   throw Not_Implemented("Hash to curve is not implemented for this curve");
}

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::from_params(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) {
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(p), "p is not prime");
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(order), "order is not prime");
   BOTAN_ARG_CHECK(a >= 0 && a < p, "a is invalid");
   BOTAN_ARG_CHECK(b > 0 && b < p, "b is invalid");
   BOTAN_ARG_CHECK(base_x >= 0 && base_x < p, "base_x is invalid");
   BOTAN_ARG_CHECK(base_y >= 0 && base_y < p, "base_y is invalid");

   const size_t p_bits = p.bits();

   // Same size restriction as EC_Group:
   // Must be either exactly P-512 or else in 128..512 bits multiple of 32
   if(p_bits == 512) {
      if(p != BigInt::power_of_2(521) - 1) {
         return {};
      }
   } else if(p_bits < 128 || p_bits > 512 || p_bits % 32 != 0) {
      return {};
   }

   // We don't want to deal with Shanks-Tonelli in the generic case
   if(p % 4 != 3) {
      return {};
   }

   // The bit length of the field and order being the same simplifies things
   if(p_bits != order.bits()) {
      return {};
   }

   return std::make_shared<GenericPrimeOrderCurve>(p, a, b, base_x, base_y, order);
}

}  // namespace Botan::PCurve
