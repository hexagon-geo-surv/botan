/*
* Modular Reducer
* (C) 1999-2010,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MODULAR_REDUCER_H_
#define BOTAN_MODULAR_REDUCER_H_

#include <botan/bigint.h>

BOTAN_FUTURE_INTERNAL_HEADER(reducer.h)

namespace Botan {

/**
* Modular Reduction (using Barrett's technique)
*/
class BOTAN_PUBLIC_API(2, 0) Modular_Reducer final {
   public:
      /**
      * Perform modular reduction of x
      *
      * @note If x is non-negative and no greater than modulus^2 then the algorithm
      * attempts to avoid side channels. Side channel security is not guaranteed for
      * inputs that are negative or larger than the square of the modulus.
      */
      BigInt reduce(const BigInt& x) const;

      /**
      * Multiply mod p
      * @param x the first operand
      * @param y the second operand
      * @return (x * y) % p
      *
      * @note If both x and y are non-negative and also less than modulus, then
      * the algorithm attempts to avoid side channels. Side channel security is not
      * guaranteed for inputs that are either negative or larger than the modulus.
      */
      BigInt multiply(const BigInt& x, const BigInt& y) const;

      /**
      * Multiply mod p
      * @return (x * y * z) % p
      *
      * TODO(Botan4) remove this
      */
      BigInt multiply(const BigInt& x, const BigInt& y, const BigInt& z) const { return multiply(x, multiply(y, z)); }

      /**
      * Square mod p
      * @param x the value to square
      * @return (x * x) % p
      *
      * @note If x is non-negative and less than modulus, then the algorithm
      * attempts to avoid side channels. Side channel security is not guaranteed
      * for inputs that are either negative or larger than the modulus.
      */
      BigInt square(const BigInt& x) const;

      /**
      * Cube mod p
      * @param x the value to cube
      * @return (x * x * x) % p
      *
      * TODO(Botan4) remove this
      */
      BigInt cube(const BigInt& x) const { return multiply(x, this->square(x)); }

      /**
      * Low level reduction function. Mostly for internal use.
      * Sometimes useful for performance by reducing temporaries
      * Reduce x mod p and place the output in out.
      *
      * @warning X and out must not reference each other
      *
      * ws is a temporary workspace.
      *
      * TODO(Botan4) make this function private
      */
      void reduce(BigInt& out, const BigInt& x, secure_vector<word>& ws) const;

      /*
      * TODO(Botan4) remove this
      */
      bool initialized() const { return (m_mod_words != 0); }

      BOTAN_DEPRECATED("Use for_public_modulus or for_secret_modulus") Modular_Reducer() { m_mod_words = 0; }

      /**
      * Accepts m == 0 and leaves the Modular_Reducer in an uninitialized state
      */
      BOTAN_DEPRECATED("Use for_public_modulus or for_secret_modulus") explicit Modular_Reducer(const BigInt& mod);

      /**
      * TODO(Botan4) remove this
      */
      const BigInt& get_modulus() const { return m_modulus; }

      /**
      * Setup for reduction where the modulus itself is public
      *
      * Requires that m > 0
      */
      static Modular_Reducer for_public_modulus(const BigInt& m);

      /**
      * Setup for reduction where the modulus itself is secret.
      *
      * This is slower than for_public_modulus since it must avoid using
      * variable time division.
      *
      * Requires that m > 0
      */
      static Modular_Reducer for_secret_modulus(const BigInt& m);

   private:
      Modular_Reducer(const BigInt& m, BigInt mu, size_t mw) : m_modulus(m), m_mu(std::move(mu)), m_mod_words(mw) {}

      BigInt m_modulus, m_mu;
      size_t m_mod_words;
};

}  // namespace Botan

#endif
