/*
* (C) 1999-2011,2018,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/barrett.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/divide.h>
#include <botan/internal/mp_core.h>

namespace Botan {

Barrett_Reduction Barrett_Reduction::for_secret_modulus(const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "Modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "Modulus cannot be negative");

   size_t mod_words = mod.sig_words();

   // Compute mu = floor(2^{2k} / m)
   const size_t mu_bits = 2 * WordInfo<word>::bits * mod_words;
   return Barrett_Reduction(mod, ct_divide_pow2k(mu_bits, mod), mod_words);
}

Barrett_Reduction Barrett_Reduction::for_public_modulus(const BigInt& mod) {
   BOTAN_ARG_CHECK(!mod.is_zero(), "Modulus cannot be zero");
   BOTAN_ARG_CHECK(!mod.is_negative(), "Modulus cannot be negative");

   size_t mod_words = mod.sig_words();

   // Compute mu = floor(2^{2k} / m)
   const size_t mu_bits = 2 * WordInfo<word>::bits * mod_words;
   return Barrett_Reduction(mod, BigInt::power_of_2(mu_bits) / mod, mod_words);
}

BigInt Barrett_Reduction::reduce(const BigInt& x) const {
   BigInt r;
   secure_vector<word> ws;
   reduce(r, x, ws);
   return r;
}

namespace {

/*
* Return x_words.subspan(mod_words - 1) in a secure_vector of size mod_words + 1
*
* This function assumes that the significant size of x_words (ie the number of
* words with a value other than zero) is at most 2 * mod_words. In any case, any
* larger value cannot be reduced using Barrett reduction; callers should have
* already checked for this and delegated to ct_modulo instead.
*/
secure_vector<word> barrett_init_shift(size_t mod_words, std::span<const word> x_words) {
   secure_vector<word> r(mod_words + 1);

   const size_t usable_words = std::min(x_words.size(), 2 * mod_words);

   if(usable_words >= mod_words - 1) {
      copy_mem(r.data(), x_words.data() + (mod_words - 1), usable_words - (mod_words - 1));
   }

   return r;
}

BigInt barrett_reduce(
   size_t mod_words, const BigInt& modulus, const BigInt& mu, std::span<const word> x_words, secure_vector<word>& ws) {
   // Divide x by 2^(W*(mw - 1)) which is equivalent to ignoring the low words
#if 0
   BigInt r = BigInt::_from_words(x_words.subspan(mod_words - 1));
   r >>= (WordInfo<word>::bits * (mod_words - 1));
#else
   BigInt r = BigInt::_from_words(barrett_init_shift(mod_words, x_words));
#endif

   // Now multiply by mu and divide again
   r.mul(mu, ws);
   r >>= (WordInfo<word>::bits * (mod_words + 1));

   // TODO add masked mul to avoid computing high bits
   r.mul(modulus, ws);
   r.mask_bits(WordInfo<word>::bits * (mod_words + 1));

   r.rev_sub(x_words.data(), std::min(x_words.size(), mod_words + 1), ws);

   /*
   * If r < 0 then we must add b^(k+1) where b = 2^w. To avoid a
   * side channel perform the addition unconditionally, with ws set
   * to either b^(k+1) or else 0.
   */
   const word r_neg = r.is_negative();

   if(ws.size() < mod_words + 2) {
      ws.resize(mod_words + 2);
   }
   clear_mem(ws.data(), ws.size());
   ws[mod_words + 1] = r_neg;

   r.add(ws.data(), mod_words + 2, BigInt::Positive);

   BOTAN_DEBUG_ASSERT(r.is_positive());
   BOTAN_DEBUG_ASSERT(r.size() >= mod_words + 1);

   clear_mem(ws.data(), ws.size());

   // Per HAC this step requires at most 2 subtractions
   const size_t bound = 2;

   for(size_t i = 0; i != bound; ++i) {
      word borrow = bigint_sub3(ws.data(), r._data(), mod_words + 1, modulus._data(), mod_words);
      CT::Mask<word>::is_zero(borrow).select_n(r.mutable_data(), ws.data(), r._data(), mod_words + 1);
   }

   return r;
}

}  // namespace

BigInt Barrett_Reduction::multiply(const BigInt& x, const BigInt& y) const {
   // TODO(Botan4) remove this block; we'll require 0 <= x < m && 0 <= y < m
   if(x > m_modulus || y > m_modulus || x.is_negative() || y.is_negative()) {
      return ct_modulo(x * y, m_modulus);
   }

   BOTAN_DEBUG_ASSERT(x.is_positive());
   BOTAN_DEBUG_ASSERT(x < m_modulus);
   BOTAN_DEBUG_ASSERT(y.is_positive());
   BOTAN_DEBUG_ASSERT(y < m_modulus);

   secure_vector<word> ws(2 * m_mod_words);

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
                 ws.data(),
                 ws.size());

      return BigInt::_from_words(std::move(z));
   }();

   // TODO(Botan4) remove this; instead require x and y be positive
   xy.cond_flip_sign(xy.is_nonzero() && x.sign() != y.sign());

   BigInt r;
   reduce(r, xy, ws);
   return r;
}

BigInt Barrett_Reduction::square(const BigInt& x) const {
   // TODO(Botan4) remove this block; we'll require 0 <= x < m
   if(x.is_negative() || x >= m_modulus) {
      return ct_modulo(x * x, m_modulus);
   }

   BOTAN_DEBUG_ASSERT(x.is_positive());
   BOTAN_DEBUG_ASSERT(x < m_modulus);

   secure_vector<word> ws(2 * m_mod_words);

   // First compute x^2
   BigInt x2 = [&]() {
      secure_vector<word> z(2 * m_mod_words);

      bigint_sqr(z.data(), z.size(), x._data(), x.size(), std::min(x.size(), m_mod_words), ws.data(), ws.size());

      return BigInt::_from_words(std::move(z));
   }();

   BigInt r;
   reduce(r, x2, ws);
   return r;
}

void Barrett_Reduction::reduce(BigInt& t1, const BigInt& x, secure_vector<word>& ws) const {
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

   t1 = barrett_reduce(m_mod_words, m_modulus, m_mu, x._as_span(), ws);

   // We do not guarantee constant-time behavior in this case
   // TODO(Botan4) can be removed entirely once x being non-negative is enforced
   if(x.is_negative()) {
      if(t1.is_nonzero()) {
         t1.rev_sub(m_modulus._data(), m_mod_words, ws);
      }
   }
}

}  // namespace Botan
