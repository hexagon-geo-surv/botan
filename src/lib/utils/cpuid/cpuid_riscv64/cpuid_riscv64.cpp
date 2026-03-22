/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>

#include <botan/assert.h>
#include <botan/internal/os_utils.h>

#if defined(BOTAN_TARGET_OS_IS_LINUX) && __has_include(<sys/hwprobe.h>)
   #include <asm/hwprobe.h>
   #include <sys/hwprobe.h>

   #define BOTAN_TARGET_HAS_RISCV_HWPROBE
#endif

namespace Botan {

namespace {

template <std::convertible_to<uint64_t>... Bs>
   requires(sizeof...(Bs) > 0)
constexpr uint64_t bitflag(Bs... bs) {
   return ((uint64_t(1) << bs) | ...);
}

}  // namespace

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   uint32_t feat = 0;

#if defined(BOTAN_TARGET_HAS_RISCV_HWPROBE)
   /*
   * RISCV_HWPROBE_KEY_IMA_EXT_0 bit positions
   * (https://docs.kernel.org/arch/riscv/hwprobe.html):
   *
   *  2: V      (vector)
   *  3: Zba    (address bit manipulation)
   *  4: Zbb    (basic bit manipulation)
   *  7: Zbc    (carryless multiplication: clmul, clmulh, clmulr)
   *  9: Zbkc   (carryless mul for crypto: clmul, clmulh)
   * 11: Zknd   (AES decryption)
   * 12: Zkne   (AES encryption)
   * 13: Zknh   (SHA-2: SHA-256 and SHA-512)
   * 14: Zksed  (SM4 block cipher)
   * 15: Zksh   (SM3 hash)
   * 16: Zkt    (data-independent timing)
   * 17: Zvbb   (vector basic bit manipulation)
   * 18: Zvbc   (vector carryless multiplication)
   * 20: Zvkg   (vector GCM/GMAC)
   * 21: Zvkned (vector AES)
   * 22: Zvknha (vector SHA-256)
   * 23: Zvknhb (vector SHA-512, superset of Zvknha)
   * 24: Zvksed (vector SM4)
   * 25: Zvksh  (vector SM3)
   * 26: Zvkt   (vector data-independent timing)
   *
   * For scalar operations we require additionally Zba (bit 3), Zbb (bit 4),
   * and Zkt (bit 16)
   *
   * For vector operations we require V (bit 2), Vbb (bit 17), VZkt (bit 26)
   */
   enum class RISCV_HWPROBE_bit : uint64_t {
      Scalar_AES = bitflag(3, 4, 16, 11, 12),
      Scalar_SHA2 = bitflag(3, 4, 16, 13),
      Scalar_SM4 = bitflag(3, 4, 16, 14),
      Scalar_SM3 = bitflag(3, 4, 16, 15),
      Scalar_CLMUL_Zbc = bitflag(3, 4, 16, 7),
      Scalar_CLMUL_Zbkc = bitflag(3, 4, 16, 9),

      Vector = bitflag(2, 17, 26),
      Vector_AES = bitflag(2, 17, 26, 21),
      Vector_SHA256 = bitflag(2, 17, 26, 22),
      Vector_SHA512 = bitflag(2, 17, 26, 23),
      Vector_SM4 = bitflag(2, 17, 26, 24),
      Vector_SM3 = bitflag(2, 17, 26, 25),
      Vector_CLMUL = bitflag(2, 17, 26, 18),
      Vector_GCM = bitflag(2, 17, 26, 20),
   };

   struct riscv_hwprobe p;
   p.key = RISCV_HWPROBE_KEY_IMA_EXT_0;

   if(__riscv_hwprobe(&p, 1, 0, nullptr, 0) == 0) {
      const uint64_t riscv_features = p.value;

      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_AES, CPUFeature::Bit::SCALAR_AES, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_SHA2, CPUFeature::Bit::SCALAR_SHA256, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_SHA2, CPUFeature::Bit::SCALAR_SHA512, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_SM3, CPUFeature::Bit::SCALAR_SM3, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_SM4, CPUFeature::Bit::SCALAR_SM4, allowed);

      // Detect carryless multiplication via either Zbc or Zbkc
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_CLMUL_Zbc, CPUFeature::Bit::SCALAR_CLMUL, allowed);
      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Scalar_CLMUL_Zbkc, CPUFeature::Bit::SCALAR_CLMUL, allowed);

      feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector, CPUFeature::Bit::VECTOR, allowed);

      if(is_set(feat, CPUFeature::Bit::VECTOR)) {
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_AES, CPUFeature::Bit::VECTOR_AES, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_SHA256, CPUFeature::Bit::VECTOR_SHA256, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_SHA512, CPUFeature::Bit::VECTOR_SHA512, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_SM3, CPUFeature::Bit::VECTOR_SM3, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_SM4, CPUFeature::Bit::VECTOR_SM4, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_CLMUL, CPUFeature::Bit::VECTOR_CLMUL, allowed);
         feat |= if_set(riscv_features, RISCV_HWPROBE_bit::Vector_GCM, CPUFeature::Bit::VECTOR_GCM, allowed);
      }
   }
#else
   BOTAN_UNUSED(allowed);
#endif

   return feat;
}

}  // namespace Botan
