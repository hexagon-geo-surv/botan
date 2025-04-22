/*
* Modular Reducer
* (C) 1999-2010,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MODULAR_REDUCER_H_
#define BOTAN_MODULAR_REDUCER_H_

#include <botan/bigint.h>

BOTAN_DEPRECATED_HEADER("reducer.h")

namespace Botan {

/**
* Modular Reduction
*
* This interface is no longer used within the library and is not considered
* in-scope for what the public API should support. It is expected this class
* and this entire header will be removed in Botan4.
*
* TODO(Botan4) delete this file
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
      BigInt multiply(const BigInt& x, const BigInt& y) const { return reduce(x * y); }

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
      BigInt square(const BigInt& x) const { return reduce(x * x); }

      /**
      * Cube mod p
      * @param x the value to cube
      * @return (x * x * x) % p
      *
      * TODO(Botan4) remove this
      */
      BigInt cube(const BigInt& x) const { return multiply(x, this->square(x)); }

      bool initialized() const { return m_modulus.is_nonzero(); }

      Modular_Reducer() = default;

      /**
      * Accepts m == 0 which leaves the Modular_Reducer in an uninitialized state
      */
      explicit Modular_Reducer(const BigInt& mod);

      const BigInt& get_modulus() const { return m_modulus; }

      /**
      * Setup for reduction where the modulus itself is public
      *
      * Requires that m > 0
      */
      static Modular_Reducer for_public_modulus(const BigInt& m) { return Modular_Reducer(m); }

      /**
      * Setup for reduction where the modulus itself is secret.
      *
      * This is slower than for_public_modulus since it must avoid using
      * variable time division.
      *
      * Requires that m > 0
      */
      static Modular_Reducer for_secret_modulus(const BigInt& m) { return Modular_Reducer(m); }

      /**
      * Old reduction function. No advantage vs using plain reduce
      */
      void reduce(BigInt& out, const BigInt& x, secure_vector<word>& /*ws*/) const {
         out = reduce(x);
      }

   private:
      BigInt m_modulus;
};

}  // namespace Botan

#endif
