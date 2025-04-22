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
   BigInt r = BigInt::_from_words(barrett_init_shift(mod_words, x_words));

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
   // XXX comparison might be expensive here
   BOTAN_ARG_CHECK(x.is_positive() && x < m_modulus, "Invalid x param for Barrett multiply");
   BOTAN_ARG_CHECK(y.is_positive() && y < m_modulus, "Invalid y param for Barrett multiply");

   secure_vector<word> ws(2 * m_mod_words);
   secure_vector<word> xy(2 * m_mod_words);

   bigint_mul(xy.data(),
              xy.size(),
              x._data(),
              x.size(),
              std::min(x.size(), m_mod_words),
              y._data(),
              y.size(),
              std::min(y.size(), m_mod_words),
              ws.data(),
              ws.size());

   return barrett_reduce(m_mod_words, m_modulus, m_mu, xy, ws);
}

BigInt Barrett_Reduction::square(const BigInt& x) const {
   // XXX comparison might be expensive here
   BOTAN_ARG_CHECK(x.is_positive() && x < m_modulus, "Invalid x param for Barrett square");

   secure_vector<word> ws(2 * m_mod_words);
   secure_vector<word> x2(2 * m_mod_words);

   bigint_sqr(x2.data(), x2.size(), x._data(), x.size(), std::min(x.size(), m_mod_words), ws.data(), ws.size());

   return barrett_reduce(m_mod_words, m_modulus, m_mu, x2, ws);
}

BigInt Barrett_Reduction::reduce(const BigInt& x) const {
   BOTAN_ARG_CHECK(x.is_positive(), "Argument must be positive");

   const size_t x_sw = x.sig_words();

   // TODO(Botan4) can be removed entirely once the restriction is enforced
   if(x_sw > 2 * m_mod_words) {
      // too big, fall back to slow boat division
      printf("chonky!\n");
      return ct_modulo(x, m_modulus);
   }

   BOTAN_ARG_CHECK(x_sw <= 2 * m_mod_words, "Barrett reduction input too large to handle");

   secure_vector<word> ws;
   return barrett_reduce(m_mod_words, m_modulus, m_mu, x._as_span(), ws);
}

}  // namespace Botan
