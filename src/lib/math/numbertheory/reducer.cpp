/*
* Modular Reducer
* (C) 1999-2011,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/reducer.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/mp_core.h>

namespace Botan {

/*
* Modular_Reducer Constructor
*/
Modular_Reducer::Modular_Reducer(const BigInt& mod) {
   if(mod < 0) {
      throw Invalid_Argument("Modular_Reducer: modulus must be positive");
   }

   // Left uninitialized if mod == 0
   m_mod_words = 0;

   if(mod > 0) {
      *this = Modular_Reducer::for_secret_modulus(mod);
   }
}

Modular_Reducer Modular_Reducer::for_secret_modulus(const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "Modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "Modulus cannot be negative");

   size_t mod_words = mod.sig_words();

   // Compute mu = floor(2^{2k} / m)
   const size_t mu_bits = 2 * WordInfo<word>::bits * mod_words;
   return Modular_Reducer(mod, ct_divide_pow2k(mu_bits, mod), mod_words);
}

Modular_Reducer Modular_Reducer::for_public_modulus(const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "Modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "Modulus cannot be negative");

   size_t mod_words = mod.sig_words();

   // Compute mu = floor(2^{2k} / m)
   const size_t mu_bits = 2 * WordInfo<word>::bits * mod_words;
   return Modular_Reducer(mod, BigInt::power_of_2(mu_bits) / mod, mod_words);
}

BigInt Modular_Reducer::reduce(const BigInt& x) const {
   BigInt r;
   secure_vector<word> ws;
   reduce(r, x, ws);
   return r;
}

BigInt Modular_Reducer::multiply(const BigInt& x, const BigInt& y) const {

   // TODO(Botan4) remove this block; we'll require 0 <= x < m && 0 <= y < m
   if(x > m_modulus || y > m_modulus || x.is_negative() || y.is_negative()) {
      return reduce(x * y);
   }

   BOTAN_DEBUG_ASSERT(x < m_modulus);
   BOTAN_DEBUG_ASSERT(y < m_modulus);

   secure_vector<word> ws(2 * m_mod_words);

   // First compute x*y

   BigInt xy = [&]() {
      secure_vector<word> z(2 * m_mod_words);

      bigint_mul(z.data(),
                 z.size(),
                 x._data(),
                 x.size(),
                 std::min(x.size(), m_mod_words),
                 y._data(),
                 y.size(),
                 std::min(y.size(), m_mod_words),
                 ws.data(), ws.size());

      return BigInt::_from_words(std::move(z));
   }();

   // TODO(Botan4) remove this; instead require x and y be positive
   xy.cond_flip_sign(xy.is_nonzero() && x.sign() != y.sign());

   BigInt r;
   reduce(r, xy, ws);
   return r;
}

BigInt Modular_Reducer::square(const BigInt& x) const {
   BOTAN_ASSERT_NOMSG(x < m_modulus); // TODO DEBUG_ASSERT

   secure_vector<word> ws(2 * m_mod_words);

   // First compute x^2
   BigInt x2 = [&]() {
      secure_vector<word> z(2 * m_mod_words);

      bigint_sqr(z.data(),
                 z.size(),
                 x._data(),
                 x.size(),
                 std::min(x.size(), m_mod_words),
                 ws.data(), ws.size());

      return BigInt::_from_words(std::move(z));
   }();

   BigInt r;
   reduce(r, x2, ws);
   return r;
}

void Modular_Reducer::reduce(BigInt& t1, const BigInt& x, secure_vector<word>& ws) const {
   // TODO(Botan4) this can be removed once the default constructor is gone
   if(m_mod_words == 0) {
      throw Invalid_State("Modular_Reducer: Never initalized");
   }

   BOTAN_ARG_CHECK(&t1 != &x, "Arguments cannot alias");

   // TODO(Botan4) add this requirement for callers
   // BOTAN_ARG_CHECK(x.is_positive(), "Argument must be positive");

   const size_t x_sw = x.sig_words();

   // TODO(Botan4) can be removed entirely once the restriction is enforced
   if(x_sw > 2 * m_mod_words) {
      // too big, fall back to slow boat division
      t1 = ct_modulo(x, m_modulus);
      return;
   }

   // Divide x by 2^(W*(mw - 1)) then multiply by mu
   t1 = x;
   t1.set_sign(BigInt::Positive);
   t1 >>= (WordInfo<word>::bits * (m_mod_words - 1));

   t1.mul(m_mu, ws);
   t1 >>= (WordInfo<word>::bits * (m_mod_words + 1));

   // TODO add masked mul to avoid computing high bits
   t1.mul(m_modulus, ws);
   t1.mask_bits(WordInfo<word>::bits * (m_mod_words + 1));

   t1.rev_sub(x._data(), std::min(x_sw, m_mod_words + 1), ws);

   /*
   * If t1 < 0 then we must add b^(k+1) where b = 2^w. To avoid a
   * side channel perform the addition unconditionally, with ws set
   * to either b^(k+1) or else 0.
   */
   const word t1_neg = t1.is_negative();

   if(ws.size() < m_mod_words + 2) {
      ws.resize(m_mod_words + 2);
   }
   clear_mem(ws.data(), ws.size());
   ws[m_mod_words + 1] = t1_neg;

   t1.add(ws.data(), m_mod_words + 2, BigInt::Positive);

   // Per HAC this step requires at most 2 subtractions
   t1.ct_reduce_below(m_modulus, ws, 2);

   // We do not guarantee constant-time behavior in this case
   // TODO(Botan4) can be removed entirely once x being non-negative is enforced
   if(x.is_negative()) {
      if(t1.is_nonzero()) {
         t1.rev_sub(m_modulus._data(), m_mod_words, ws);
      }
   }
}

}  // namespace Botan
