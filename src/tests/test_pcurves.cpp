/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PCURVES)
   #include "test_rng.h"
   #include <botan/hash.h>
   #include <botan/mem_ops.h>
   #include <botan/internal/pcurves.h>
   #include <botan/internal/stl_util.h>
#endif

#if defined(BOTAN_HAS_PCURVES_GENERIC)
   #include <botan/bigint.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_PCURVES)

class Pcurve_Basemul_Tests final : public Text_Based_Test {
   public:
      Pcurve_Basemul_Tests() : Text_Based_Test("pubkey/ecc_base_point_mul.vec", "k,P") {}

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override {
         Test::Result result("Pcurves base point multiply " + group_id);

         const auto k_bytes = vars.get_req_bin("k");
         const auto P_bytes = vars.get_req_bin("P");

         auto& rng = Test::rng();
         Botan::Null_RNG null_rng;

         if(auto curve = Botan::PCurve::PrimeOrderCurve::from_name(group_id)) {
            if(auto scalar = curve->deserialize_scalar(k_bytes)) {
               const auto k = scalar.value();
               auto pt2 = curve->mul_by_g(k, rng).to_affine().serialize();
               result.test_eq("mul_by_g correct", pt2, P_bytes);

               auto pt3 = curve->mul_by_g(k, null_rng).to_affine().serialize();
               result.test_eq("mul_by_g (Null_RNG) correct", pt3, P_bytes);

               auto g = curve->generator();
               auto pt4 = curve->mul(g, k, rng).to_affine().serialize();
               result.test_eq("mul correct", pt4, P_bytes);

               auto pt5 = curve->mul(g, k, null_rng).to_affine().serialize();
               result.test_eq("mul correct (Null_RNG)", pt5, P_bytes);

               // Now test the var point mul with a blinded point ((g*b)*k)/b = pt
               auto b = curve->random_scalar(rng);
               auto binv = b.invert();
               auto gx = curve->mul_by_g(b, rng).to_affine();
               auto gx_k = curve->mul(gx, k, rng).to_affine();
               auto g_k = curve->mul(gx_k, binv, rng).to_affine();
               result.test_eq("blinded mul correct", g_k.serialize(), P_bytes);
            } else {
               result.test_failure("Curve rejected scalar input");
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pcurves", "pcurves_basemul", Pcurve_Basemul_Tests);

class Pcurve_Ecdh_Tests final : public Text_Based_Test {
   public:
      Pcurve_Ecdh_Tests() : Text_Based_Test("pubkey/ecdh.vec", "Secret,CounterKey,K") {}

      Test::Result run_one_test(const std::string& group_id, const VarMap& vars) override {
         Test::Result result("Pcurves ECDH " + group_id);

         const auto sk = vars.get_req_bin("Secret");
         const auto peer_key = vars.get_req_bin("CounterKey");
         const auto shared_secret = vars.get_req_bin("K");

         auto curve = Botan::PCurve::PrimeOrderCurve::from_name(group_id);

         if(!curve) {
            result.test_note("Skipping test due to missing pcurve " + group_id);
            return result;
         }

         auto x = curve->deserialize_scalar(sk);
         auto pt = curve->deserialize_point(peer_key);

         if(x && pt) {
            auto ss = curve->mul(pt.value(), x.value(), rng()).to_affine().x_bytes();
            result.test_eq("shared secret", ss, shared_secret);
         } else {
            result.test_failure("Curve rejected test inputs");
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pcurves", "pcurves_ecdh", Pcurve_Ecdh_Tests);

class Pcurve_Arithmetic_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         auto& rng = Test::rng();

         for(auto curve_id : Botan::PCurve::PrimeOrderCurveId::all()) {
            Test::Result result("Pcurves point operations " + curve_id.to_string());

            result.start_timer();

            auto curve = Botan::PCurve::PrimeOrderCurve::from_id(curve_id);

            if(!curve) {
               result.test_note("Skipping test due to missing pcurve " + curve_id.to_string());
               continue;
            }

            const auto zero = curve->scalar_zero();
            const auto one = curve->scalar_one();
            const auto g = curve->generator();
            const auto g_bytes = g.serialize();

            const auto id = curve->mul_by_g(zero, rng);
            result.confirm("g*zero is point at identity", id.to_affine().is_identity());

            const auto id2 = id.dbl();
            result.confirm("identity * 2 is identity", id2.to_affine().is_identity());

            const auto id3 = id2 + id;
            result.confirm("identity plus itself is identity", id3.to_affine().is_identity());

            const auto g_one = curve->mul_by_g(one, rng);
            result.test_eq("g*one == generator", g_one.to_affine().serialize(), g_bytes);

            const auto g_plus_id = g_one + id;
            result.test_eq("g + id == g", g_plus_id.to_affine().serialize(), g_bytes);

            const auto g_plus_ida = g_one + id.to_affine();
            result.test_eq("g + id (affine) == g", g_plus_ida.to_affine().serialize(), g_bytes);

            const auto id_plus_g = id + g_one;
            result.test_eq("id + g == g", id_plus_g.to_affine().serialize(), g_bytes);

            const auto id_plus_ga = id + g_one.to_affine();
            result.test_eq("id + g (affine) == g", id_plus_ga.to_affine().serialize(), g_bytes);

            const auto g_neg_one = curve->mul_by_g(one.negate(), rng).to_affine();

            const auto id_from_g = g_one + g_neg_one;
            result.confirm("g - g is identity", id_from_g.to_affine().is_identity());

            const auto g_two = curve->mul_by_g(one + one, rng);
            const auto g_plus_g = g_one + g_one;
            result.test_eq("2*g == g+g", g_two.to_affine().serialize(), g_plus_g.to_affine().serialize());

            result.confirm("Scalar::zero is zero", zero.is_zero());
            result.confirm("(zero+zero) is zero", (zero + zero).is_zero());
            result.confirm("(zero*zero) is zero", (zero * zero).is_zero());
            result.confirm("(zero-zero) is zero", (zero - zero).is_zero());

            const auto neg_zero = zero.negate();
            result.confirm("zero.negate() is zero", neg_zero.is_zero());

            result.confirm("(zero+nz) is zero", (zero + neg_zero).is_zero());
            result.confirm("(nz+nz) is zero", (neg_zero + neg_zero).is_zero());
            result.confirm("(nz+zero) is zero", (neg_zero + zero).is_zero());

            result.confirm("Scalar::one is not zero", !one.is_zero());
            result.confirm("(one-one) is zero", (one - one).is_zero());
            result.confirm("(one+one.negate()) is zero", (one + one.negate()).is_zero());
            result.confirm("(one.negate()+one) is zero", (one.negate() + one).is_zero());

            for(size_t i = 0; i != 16; ++i) {
               const auto pt = curve->mul_by_g(curve->random_scalar(rng), rng).to_affine();

               const auto a = curve->random_scalar(rng);
               const auto b = curve->random_scalar(rng);
               const auto c = a + b;

               const auto Pa = curve->mul(pt, a, rng);
               const auto Pb = curve->mul(pt, b, rng);
               const auto Pc = curve->mul(pt, c, rng);

               const auto Pc_bytes = Pc.to_affine().serialize();

               const auto Pab = Pa + Pb;
               result.test_eq("Pa + Pb == Pc", Pab.to_affine().serialize(), Pc_bytes);

               const auto Pba = Pb + Pa;
               result.test_eq("Pb + Pa == Pc", Pba.to_affine().serialize(), Pc_bytes);

               const auto Pabm = Pa + Pb.to_affine();
               result.test_eq("Pa + Pb == Pc (mixed)", Pabm.to_affine().serialize(), Pc_bytes);
               const auto Pbam = Pb + Pa.to_affine();
               result.test_eq("Pb + Pa == Pc (mixed)", Pbam.to_affine().serialize(), Pc_bytes);
            }

            for(size_t i = 0; i != 16; ++i) {
               const auto pt1 = curve->mul_by_g(curve->random_scalar(rng), rng).to_affine();
               const auto pt2 = curve->mul_by_g(curve->random_scalar(rng), rng).to_affine();

               const auto s1 = curve->random_scalar(rng);
               const auto s2 = curve->random_scalar(rng);

               const auto mul2_table = curve->mul2_setup(pt1, pt2);

               const auto ref = (curve->mul(pt1, s1, rng) + curve->mul(pt2, s2, rng)).to_affine();

               if(auto mul2pt = curve->mul2_vartime(*mul2_table, s1, s2)) {
                  result.test_eq("ref == mul2t", ref.serialize(), mul2pt->to_affine().serialize());
               } else {
                  result.confirm("ref is identity", ref.is_identity());
               }
            }

            // Test cases where the two points have a linear relation
            for(size_t i = 0; i != 16; ++i) {
               const auto pt1 = curve->generator();

               auto pt2 = [&]() {
                  const auto lo = [&]() {
                     if((i / 2) == 0) {
                        return curve->scalar_zero();
                     } else {
                        std::vector<uint8_t> sbytes(curve->scalar_bytes());
                        sbytes[sbytes.size() - 1] = static_cast<uint8_t>(i / 2);
                        return curve->deserialize_scalar(sbytes).value();
                     }
                  }();
                  auto x = curve->mul_by_g(lo, rng).to_affine();
                  if(i % 2 == 0) {
                     x = x.negate();
                  }
                  return x;
               }();

               const auto s1 = curve->random_scalar(rng);
               const auto s2 = curve->random_scalar(rng);

               const auto mul2_table = curve->mul2_setup(pt1, pt2);

               const auto ref = (curve->mul(pt1, s1, rng) + curve->mul(pt2, s2, rng)).to_affine();

               if(auto mul2pt = curve->mul2_vartime(*mul2_table, s1, s2)) {
                  result.test_eq("ref == mul2t", ref.serialize(), mul2pt->to_affine().serialize());
               } else {
                  result.confirm("ref is identity", ref.is_identity());
               }
            }

            result.end_timer();

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pcurves", "pcurves_arith", Pcurve_Arithmetic_Tests);

class Pcurve_Scalar_Math_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         auto& rng = Test::rng();

         for(auto curve_id : Botan::PCurve::PrimeOrderCurveId::all()) {
            Test::Result result("Pcurves scalar arithmetic " + curve_id.to_string());

            auto curve = Botan::PCurve::PrimeOrderCurve::from_id(curve_id);

            if(curve) {
               test_scalar_math(result, curve, rng);
            } else {
               result.test_note("Skipping test due to missing pcurve " + curve_id.to_string());
            }

            results.push_back(result);
         }

#if defined(BOTAN_HAS_PCURVES_GENERIC)
         Test::Result result("Pcurves scalar arithmetic BADA55-256");
         auto curve = Botan::PCurve::PrimeOrderCurve::from_params(
            Botan::BigInt::from_string("0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c03"),
            Botan::BigInt::from_string("0xf1fd178c0b3ad58f10126de8ce42435b3961adbcabc8ca6de8fcf353d86e9c00"),
            Botan::BigInt::from_string("0xbada55bada55bada55bada55bada55bada55bada55bada55bada55bada55bd48"),
            Botan::BigInt::from_string("1"),
            Botan::BigInt::from_string("2"),
            Botan::BigInt::from_string("0xf1fd178c0b3ad58f10126de8ce42435a1a8e3837861aa0efa0e52aec7379c967")
            );

         if(curve) {
            test_scalar_math(result, curve, rng);
         } else {
            result.test_failure("Failed to set up BADA55-256");
         }
         results.push_back(result);
#endif

         return results;
      }

   private:
      void test_scalar_math(Test::Result& result,
                            std::shared_ptr<const Botan::PCurve::PrimeOrderCurve> curve,
                            Botan::RandomNumberGenerator& rng) {

         result.start_timer();

         const auto zero = curve->scalar_zero();
         const auto one = curve->scalar_one();
         const auto n_one = one.negate();

         result.test_eq("Zero is zero", zero.is_zero(), true);
         result.test_eq("One is not zero", one.is_zero(), false);

         result.test_eq("1 - 1 = 0", (one - one).serialize(), zero.serialize());

         result.test_eq("1 + -1 = 0", (one + n_one).serialize(), zero.serialize());

         // Not mathematically correct, but ok for our purposes
         result.test_eq("Inverse of zero is zero", zero.invert().serialize(), zero.serialize());
         result.test_eq("Inverse of zero is zero (2)", zero.invert().is_zero(), true);

         result.test_eq("Inverse of 1 is 1", one.invert().serialize(), one.serialize());

         for(size_t i = 0; i != 16; ++i) {
            auto r = curve->random_scalar(rng);
            auto r2 = r * r;
            auto r_inv = r.invert();
            result.test_eq("r * r^-1 = 1", (r * r_inv).serialize(), one.serialize());
            result.test_eq("r^2 = r*r", r.square().serialize(), r2.serialize());
            result.test_eq("r*-1 = -r", (r * n_one).serialize(), r.negate().serialize());

            result.test_eq("(r^-1)^2 = (r^2)^-1", r_inv.square().serialize(), r2.invert().serialize());
         }

         for(size_t i = 0; i != 16; ++i) {
            auto a = curve->random_scalar(rng);
            auto b = curve->random_scalar(rng);

            auto a_plus_b = a + b;
            result.test_eq("(a + b) - b == a", (a_plus_b - b).serialize(), a.serialize());
            result.test_eq("(a + b) - a == b", (a_plus_b - a).serialize(), b.serialize());
            result.test_eq("b - (a + b) == -a", (b - a_plus_b).serialize(), a.negate().serialize());
            result.test_eq("a - (a + b) == -b", (a - a_plus_b).serialize(), b.negate().serialize());
         }

         result.end_timer();
      }
};

BOTAN_REGISTER_TEST("pcurves", "pcurves_scalar_math", Pcurve_Scalar_Math_Tests);

class Pcurve_PointEnc_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         auto& rng = Test::rng();

         for(auto id : Botan::PCurve::PrimeOrderCurveId::all()) {
            Test::Result result("Pcurves point operations " + id.to_string());

            result.start_timer();

            auto curve = Botan::PCurve::PrimeOrderCurve::from_id(id);

            if(!curve) {
               result.test_note("Skipping test due to missing pcurve " + id.to_string());
               continue;
            }

            for(size_t trial = 0; trial != 100; ++trial) {
               const auto scalar = curve->random_scalar(rng);
               const auto pt = curve->mul_by_g(scalar, rng).to_affine();

               const auto pt_u = pt.serialize();
               result.test_eq("Expected uncompressed header", static_cast<size_t>(pt_u[0]), 0x04);
               const size_t fe_bytes = (pt_u.size() - 1) / 2;
               const auto pt_c = pt.serialize_compressed();

               result.test_eq("Expected compressed size", pt_c.size(), 1 + fe_bytes);
               result.confirm("Expected compressed header", pt_c[0] == 0x02 || pt_c[0] == 0x03);

               if(auto d_pt_u = curve->deserialize_point(pt_u)) {
                  result.test_eq("Deserializing uncompressed returned correct point", d_pt_u->serialize(), pt_u);
               } else {
                  result.test_failure("Failed to deserialize uncompressed point");
               }

               if(auto d_pt_c = curve->deserialize_point(pt_c)) {
                  result.test_eq("Deserializing compressed returned correct point", d_pt_c->serialize(), pt_u);
               } else {
                  result.test_failure("Failed to deserialize compressed point");
               }
            }

            result.end_timer();

            results.push_back(result);
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pcurves", "pcurves_point_enc", Pcurve_PointEnc_Tests);

#endif

}  // namespace Botan_Tests
