/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_ALGOS_H_
#define BOTAN_PCURVES_ALGOS_H_

#include <botan/types.h>
#include <botan/internal/ct_utils.h>
#include <span>
#include <vector>

namespace Botan {

/**
* Field inversion concept
*
* This concept checks if the FieldElement supports fe_invert2
*/
template <typename C>
concept curve_supports_fe_invert2 = requires(const typename C::FieldElement& fe) {
   { C::fe_invert2(fe) } -> std::same_as<typename C::FieldElement>;
};

/**
* Field inversion
*
* Uses the specialized fe_invert2 if available, or otherwise the standard
* (FLT-based) field inversion.
*/
template <typename C>
inline constexpr auto invert_field_element(const typename C::FieldElement& fe) {
   if constexpr(curve_supports_fe_invert2<C>) {
      return C::fe_invert2(fe) * fe;
   } else {
      return fe.invert();
   }
}

/**
* Convert a projective point into affine
*/
template <typename C>
inline constexpr auto to_affine(const typename C::ProjectivePoint& pt) {
   // Not strictly required right? - default should work as long
   // as (0,0) is identity and invert returns 0 on 0

   if constexpr(curve_supports_fe_invert2<C>) {
      const auto z2_inv = C::fe_invert2(pt.z());
      const auto z3_inv = z2_inv.square() * pt.z();
      return typename C::AffinePoint(pt.x() * z2_inv, pt.y() * z3_inv);
   } else {
      const auto z_inv = invert_field_element<C>(pt.z());
      const auto z2_inv = z_inv.square();
      const auto z3_inv = z_inv * z2_inv;
      return typename C::AffinePoint(pt.x() * z2_inv, pt.y() * z3_inv);
   }
}

/**
* Convert a projective point into affine and return x coordinate only
*/
template <typename C>
auto to_affine_x(const typename C::ProjectivePoint& pt) {
   if constexpr(curve_supports_fe_invert2<C>) {
      return pt.x() * C::fe_invert2(pt.z());
   } else {
      const auto z_inv = invert_field_element<C>(pt.z());
      const auto z2_inv = z_inv.square();
      return pt.x() * z2_inv;
   }
}

template <typename C>
auto to_affine_batch(std::span<const typename C::ProjectivePoint> projective) {
   using AffinePoint = typename C::AffinePoint;

   const size_t N = projective.size();
   std::vector<AffinePoint> affine;
   affine.reserve(N);

   CT::Choice any_identity = CT::Choice::no();

   for(const auto& pt : projective) {
      any_identity = any_identity || pt.is_identity();
   }

   if(N <= 2 || any_identity.as_bool()) {
      // If there are identity elements, using the batch inversion gets
      // tricky. It can be done, but this should be a rare situation so
      // just punt to the serial conversion if it occurs
      for(size_t i = 0; i != N; ++i) {
         affine.push_back(to_affine<C>(projective[i]));
      }
   } else {
      std::vector<typename C::FieldElement> c;
      c.reserve(N);

      /*
      Batch projective->affine using Montgomery's trick

      See Algorithm 2.26 in "Guide to Elliptic Curve Cryptography"
      (Hankerson, Menezes, Vanstone)
      */

      c.push_back(projective[0].z());
      for(size_t i = 1; i != N; ++i) {
         c.push_back(c[i - 1] * projective[i].z());
      }

      auto s_inv = invert_field_element<C>(c[N - 1]);

      for(size_t i = N - 1; i > 0; --i) {
         const auto& p = projective[i];

         const auto z_inv = s_inv * c[i - 1];
         const auto z2_inv = z_inv.square();
         const auto z3_inv = z_inv * z2_inv;

         s_inv = s_inv * p.z();

         affine.push_back(AffinePoint(p.x() * z2_inv, p.y() * z3_inv));
      }

      const auto z2_inv = s_inv.square();
      const auto z3_inv = s_inv * z2_inv;
      affine.push_back(AffinePoint(projective[0].x() * z2_inv, projective[0].y() * z3_inv));
      std::reverse(affine.begin(), affine.end());
      return affine;
   }

   return affine;
}

/*
Point doubling

Using https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2

Cost (generic A): 4M + 6S + 4A + 2*2 + 1*3 + 1*4 + 1*8
Cost (A == -3):   4M + 4S + 5A + 2*2 + 1*3 + 1*4 + 1*8
Cost (A == 0):    3M + 4S + 3A + 2*2 + 1*3 + 1*4 + 1*8
*/

template <typename ProjectivePoint>
inline constexpr ProjectivePoint dbl_a_minus_3(const ProjectivePoint& pt) {
   /*
   if a == -3 then
   3*x^2 + a*z^4 == 3*x^2 - 3*z^4 == 3*(x^2-z^4) == 3*(x-z^2)*(x+z^2)
   */
   const auto z2 = pt.z().square();
   const auto m = (pt.x() - z2).mul3() * (pt.x() + z2);

   // Remaining cost: 3M + 3S + 3A + 2*2 + 1*4 + 1*8
   const auto y2 = pt.y().square();
   const auto s = pt.x().mul4() * y2;
   const auto nx = m.square() - s.mul2();
   const auto ny = m * (s - nx) - y2.square().mul8();
   const auto nz = pt.y().mul2() * pt.z();

   return ProjectivePoint(nx, ny, nz);
}

template <typename ProjectivePoint>
inline constexpr ProjectivePoint dbl_a_zero(const ProjectivePoint& pt) {
   // If a == 0 then 3*x^2 + a*z^4 == 3*x^2
   // Cost: 1S + 1*3
   const auto m = pt.x().square().mul3();

   // Remaining cost: 3M + 3S + 3A + 2*2 + 1*4 + 1*8
   const auto y2 = pt.y().square();
   const auto s = pt.x().mul4() * y2;
   const auto nx = m.square() - s.mul2();
   const auto ny = m * (s - nx) - y2.square().mul8();
   const auto nz = pt.y().mul2() * pt.z();

   return ProjectivePoint(nx, ny, nz);
}

template <typename ProjectivePoint, typename FieldElement>
inline constexpr ProjectivePoint dbl_generic(const ProjectivePoint& pt, const FieldElement& A) {
   // Cost: 1M + 3S + 1A + 1*3
   const auto z2 = pt.z().square();
   const auto m = pt.x().square().mul3() + A * z2.square();

   // Remaining cost: 3M + 3S + 3A + 2*2 + 1*4 + 1*8
   const auto y2 = pt.y().square();
   const auto s = pt.x().mul4() * y2;
   const auto nx = m.square() - s.mul2();
   const auto ny = m * (s - nx) - y2.square().mul8();
   const auto nz = pt.y().mul2() * pt.z();

   return ProjectivePoint(nx, ny, nz);
}

/*
Repeated doubling using an adaptation of Algorithm 3.23 in
"Guide To Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone)

Curiously the book gives the algorithm only for A == -3, but
the largest gains come from applying it to the generic A case,
where it saves 2 squarings per iteration.

For A == 0
Pay 1*2 + 1half to save n*(1*4 + 1*8)

For A == -3:
Pay 2S + 1*2 + 1half to save n*(1A + 1*4 + 1*8) + 1M

For generic A:
Pay 2S + 1*2 + 1half to save n*(2S + 1*4 + 1*8)
*/
template <typename ProjectivePoint>
inline constexpr ProjectivePoint dbl_n_a_minus_3(const ProjectivePoint& pt, size_t n) {
   auto nx = pt.x();
   auto ny = pt.y().mul2();
   auto nz = pt.z();
   auto w = nz.square().square();

   while(n > 0) {
      const auto ny2 = ny.square();
      const auto ny4 = ny2.square();
      const auto t1 = (nx.square() - w).mul3();
      const auto t2 = nx * ny2;
      nx = t1.square() - t2.mul2();
      nz *= ny;
      ny = t1 * (t2 - nx).mul2() - ny4;
      n--;
      if(n > 0) {
         w *= ny4;
      }
   }
   return ProjectivePoint(nx, ny.div2(), nz);
}

template <typename ProjectivePoint>
inline constexpr ProjectivePoint dbl_n_a_zero(const ProjectivePoint& pt, size_t n) {
   auto nx = pt.x();
   auto ny = pt.y().mul2();
   auto nz = pt.z();

   while(n > 0) {
      const auto ny2 = ny.square();
      const auto ny4 = ny2.square();
      const auto t1 = nx.square().mul3();
      const auto t2 = nx * ny2;
      nx = t1.square() - t2.mul2();
      nz *= ny;
      ny = t1 * (t2 - nx).mul2() - ny4;
      n--;
   }
   return ProjectivePoint(nx, ny.div2(), nz);
}

template <typename ProjectivePoint, typename FieldElement>
inline constexpr ProjectivePoint dbl_n_generic(const ProjectivePoint& pt, const FieldElement& A, size_t n) {
   auto nx = pt.x();
   auto ny = pt.y().mul2();
   auto nz = pt.z();
   auto w = nz.square().square() * A;

   while(n > 0) {
      const auto ny2 = ny.square();
      const auto ny4 = ny2.square();
      const auto t1 = nx.square().mul3() + w;
      const auto t2 = nx * ny2;
      nx = t1.square() - t2.mul2();
      nz *= ny;
      ny = t1 * (t2 - nx).mul2() - ny4;
      n--;
      if(n > 0) {
         w *= ny4;
      }
   }
   return ProjectivePoint(nx, ny.div2(), nz);
}

}  // namespace Botan

#endif
