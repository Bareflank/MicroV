#include <mv_cdl_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/touch.hpp>

namespace integration
{
    /// @brief A flag to tell if an supported feature should be printed
    constexpr auto CPUID_PRINTER_FLAG_PRINT_SUPPORTED{0x00000001_u64};
    /// @brief A flag to tell if a unsupported feature should be printed
    constexpr auto CPUID_PRINTER_FLAG_PRINT_UNSUPPORTED{0x00000002_u64};
    /// @brief A flag to tell whether or not a missing feature should error out
    constexpr auto CPUID_PRINTER_FLAG_PRINT_ERROR{0x00000004_u64};

    /// @class integration::cpuid_printer_t
    ///
    /// <!-- description -->
    ///   @brief Print CPUID features from a mv_cdl_t
    ///
    class cpuid_printer_t final
    {
        /// <!-- description -->
        /// @brief Declares register identifiers for EAX, EBX, ECX and EDX
        enum cpu_register_t : bsl::int32
        {
            REG_EAX = 0,           // NOLINT
            REG_EBX,               // NOLINT
            REG_ECX,               // NOLINT
            REG_EDX,               // NOLINT
            REG_LAST = REG_EDX,    // NOLINT
            REG_NULL = 255         // NOLINT
        };

        /// <!-- description -->
        /// @brief Declares a cpu_feature_t
        struct cpu_feature_t
        {
            /// @brief stores the CPUID function
            bsl::uint32 fun;
            /// @brief stores the CPUID index
            bsl::uint32 idx;
            /// @brief stores the CPUID register id to select a register
            cpu_register_t reg;
            /// @brief stores the CPUID bitmask of the selected register
            bsl::uint32 bitmask;
            /// @brief stores the CPUID vendor
            bsl::uint32 vendor;
            /// @brief stores the CPUID feature name
            const char *name;
        };

        /// @brief the vendor-id and largest standard function CPUID
        static constexpr auto cpuid_fn0000_0000{0x00000000_u32};
        /// @brief the CPUID function for the largest extended function
        static constexpr auto cpuid_fn8000_0000{0x80000000_u32};

        /// @brief the vendor flag for AMD
        static constexpr bsl::uint32 VENDOR_AMD{0x00000001U};    // NOLINT
        /// @brief the vendor flag for Intel
        static constexpr bsl::uint32 VENDOR_INTEL{0x00000002U};    // NOLINT
        /// @brief the vendor flag for HV_KVM
        static constexpr bsl::uint32 VENDOR_HV_KVM{0x00000004U};    // NOLINT
        /// @brief the vendor flag for HV_HYPERV
        static constexpr bsl::uint32 VENDOR_HV_HYPERV{0x00000008U};    // NOLINT
        /// @brief the vendor flag for Centaur
        static constexpr bsl::uint32 VENDOR_CENTAUR{0x00000010U};    // NOLINT
        /// @brief the any vendor flag
        static constexpr bsl::uint32 VENDOR_ANY{0xFFFFFFFFU};    // NOLINT

        /// @brief stores whether or not an supported feature should be printed
        bool m_print_supported{};
        /// @brief stores whether or not a unsupported feature should be printed
        bool m_print_unsupported{};
        /// @brief stores whether or not a missing feature should error out
        bool m_print_error{};
        /// @brief stores the vendor id VENDOR_AMD or VENDOR_INTEL
        bsl::safe_u32 m_vendor{};
        /// @brief stores the vendor name
        bsl::cstr_type m_vendor_name{};
        /// @brief stores information on whether an error occured
        bool m_has_error{};

        /// @brief stores the number of CPUID features
        static constexpr auto num_features{440_u64};
        /// @brief stores the list of CPUID features
        static constexpr bsl::array<cpu_feature_t, num_features.get()> features = {{

            // clang-format off

            /// NOTE:
            ///
            /// The data in this array is an unmodified version from
            /// https://github.com/tycho/cpuid/blob/807e78abf4f9196d587d47ec2897984e45436e44/feature.c#L67
            ///

        /*  Standard (0000_0001h) */
            { 0x00000001U, 0U, REG_EDX, 0x00000001U, VENDOR_INTEL | VENDOR_AMD, "x87 FPU on chip"},
            { 0x00000001U, 0U, REG_EDX, 0x00000002U, VENDOR_INTEL | VENDOR_AMD, "virtual-8086 mode enhancement"},
            { 0x00000001U, 0U, REG_EDX, 0x00000004U, VENDOR_INTEL | VENDOR_AMD, "debugging extensions"},
            { 0x00000001U, 0U, REG_EDX, 0x00000008U, VENDOR_INTEL | VENDOR_AMD, "page size extensions"},
            { 0x00000001U, 0U, REG_EDX, 0x00000010U, VENDOR_INTEL | VENDOR_AMD, "time stamp counter"},
            { 0x00000001U, 0U, REG_EDX, 0x00000020U, VENDOR_INTEL | VENDOR_AMD, "RDMSR and WRMSR support"},
            { 0x00000001U, 0U, REG_EDX, 0x00000040U, VENDOR_INTEL | VENDOR_AMD, "physical address extensions"},
            { 0x00000001U, 0U, REG_EDX, 0x00000080U, VENDOR_INTEL | VENDOR_AMD, "machine check exception"},
            { 0x00000001U, 0U, REG_EDX, 0x00000100U, VENDOR_INTEL | VENDOR_AMD, "CMPXCHG8B instruction"},
            { 0x00000001U, 0U, REG_EDX, 0x00000200U, VENDOR_INTEL | VENDOR_AMD, "APIC on chip"},
        /*  { 0x00000001U, 0U, REG_EDX, 0x00000400U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000001U, 0U, REG_EDX, 0x00000800U, VENDOR_INTEL | VENDOR_AMD, "SYSENTER and SYSEXIT instructions"},
            { 0x00000001U, 0U, REG_EDX, 0x00001000U, VENDOR_INTEL | VENDOR_AMD, "memory type range registers"},
            { 0x00000001U, 0U, REG_EDX, 0x00002000U, VENDOR_INTEL | VENDOR_AMD, "PTE global bit"},
            { 0x00000001U, 0U, REG_EDX, 0x00004000U, VENDOR_INTEL | VENDOR_AMD, "machine check architecture"},
            { 0x00000001U, 0U, REG_EDX, 0x00008000U, VENDOR_INTEL | VENDOR_AMD, "conditional move instruction"},
            { 0x00000001U, 0U, REG_EDX, 0x00010000U, VENDOR_INTEL | VENDOR_AMD, "page attribute table"},
            { 0x00000001U, 0U, REG_EDX, 0x00020000U, VENDOR_INTEL | VENDOR_AMD, "36-bit page size extension"},
            { 0x00000001U, 0U, REG_EDX, 0x00040000U, VENDOR_INTEL             , "processor serial number"},
            { 0x00000001U, 0U, REG_EDX, 0x00080000U, VENDOR_INTEL | VENDOR_AMD, "CLFLUSH instruction"},
        /*  { 0x00000001U, 0U, REG_EDX, 0x00100000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000001U, 0U, REG_EDX, 0x00200000U, VENDOR_INTEL             , "debug store"},
            { 0x00000001U, 0U, REG_EDX, 0x00400000U, VENDOR_INTEL             , "ACPI"},
            { 0x00000001U, 0U, REG_EDX, 0x00800000U, VENDOR_INTEL | VENDOR_AMD, "MMX instruction set"},
            { 0x00000001U, 0U, REG_EDX, 0x01000000U, VENDOR_INTEL | VENDOR_AMD, "FXSAVE/FXRSTOR instructions"},
            { 0x00000001U, 0U, REG_EDX, 0x02000000U, VENDOR_INTEL | VENDOR_AMD, "SSE instructions"},
            { 0x00000001U, 0U, REG_EDX, 0x04000000U, VENDOR_INTEL | VENDOR_AMD, "SSE2 instructions"},
            { 0x00000001U, 0U, REG_EDX, 0x08000000U, VENDOR_INTEL             , "self snoop"},
            { 0x00000001U, 0U, REG_EDX, 0x10000000U, VENDOR_INTEL | VENDOR_AMD, "max APIC IDs reserved field is valid"},
            { 0x00000001U, 0U, REG_EDX, 0x20000000U, VENDOR_INTEL             , "thermal monitor"},
        /*  { 0x00000001U, 0U, REG_EDX, 0x40000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000001U, 0U, REG_EDX, 0x80000000U, VENDOR_INTEL             , "pending break enable"},

            { 0x00000001U, 0U, REG_ECX, 0x00000001U, VENDOR_INTEL | VENDOR_AMD, "SSE3 instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x00000002U, VENDOR_INTEL | VENDOR_AMD, "PCLMULQDQ instruction"},
            { 0x00000001U, 0U, REG_ECX, 0x00000004U, VENDOR_INTEL             , "64-bit DS area"},
            { 0x00000001U, 0U, REG_ECX, 0x00000008U, VENDOR_INTEL | VENDOR_AMD, "MONITOR/MWAIT instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x00000010U, VENDOR_INTEL             , "CPL qualified debug store"},
            { 0x00000001U, 0U, REG_ECX, 0x00000020U, VENDOR_INTEL             , "virtual machine extensions"},
            { 0x00000001U, 0U, REG_ECX, 0x00000040U, VENDOR_INTEL             , "safer mode extensions"},
            { 0x00000001U, 0U, REG_ECX, 0x00000080U, VENDOR_INTEL             , "Enhanced Intel SpeedStep"},
            { 0x00000001U, 0U, REG_ECX, 0x00000100U, VENDOR_INTEL             , "thermal monitor 2"},
            { 0x00000001U, 0U, REG_ECX, 0x00000200U, VENDOR_INTEL | VENDOR_AMD, "SSSE3 instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x00000400U, VENDOR_INTEL             , "L1 context ID"},
            { 0x00000001U, 0U, REG_ECX, 0x00000800U, VENDOR_INTEL             , "silicon debug"}, /* supports IA32_DEBUG_INTERFACE MSR for silicon debug */ // NOLINT
            { 0x00000001U, 0U, REG_ECX, 0x00001000U, VENDOR_INTEL | VENDOR_AMD, "fused multiply-add AVX instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x00002000U, VENDOR_INTEL | VENDOR_AMD, "CMPXCHG16B instruction"},
            { 0x00000001U, 0U, REG_ECX, 0x00004000U, VENDOR_INTEL             , "xTPR update control"},
            { 0x00000001U, 0U, REG_ECX, 0x00008000U, VENDOR_INTEL             , "perfmon and debug capability"},
        /*  { 0x00000001U, 0U, REG_ECX, 0x00010000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000001U, 0U, REG_ECX, 0x00020000U, VENDOR_INTEL | VENDOR_AMD, "process-context identifiers"},
            { 0x00000001U, 0U, REG_ECX, 0x00040000U, VENDOR_INTEL             , "direct cache access"},
            { 0x00000001U, 0U, REG_ECX, 0x00080000U, VENDOR_INTEL | VENDOR_AMD, "SSE4.1 instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x00100000U, VENDOR_INTEL | VENDOR_AMD, "SSE4.2 instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x00200000U, VENDOR_INTEL | VENDOR_AMD, "x2APIC"},
            { 0x00000001U, 0U, REG_ECX, 0x00400000U, VENDOR_INTEL | VENDOR_AMD, "MOVBE instruction"},
            { 0x00000001U, 0U, REG_ECX, 0x00800000U, VENDOR_INTEL | VENDOR_AMD, "POPCNT instruction"},
            { 0x00000001U, 0U, REG_ECX, 0x01000000U, VENDOR_INTEL | VENDOR_AMD, "TSC deadline"},
            { 0x00000001U, 0U, REG_ECX, 0x02000000U, VENDOR_INTEL | VENDOR_AMD, "AES instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x04000000U, VENDOR_INTEL | VENDOR_AMD, "XSAVE/XRSTOR instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x08000000U, VENDOR_INTEL | VENDOR_AMD, "OS-enabled XSAVE/XRSTOR"},
            { 0x00000001U, 0U, REG_ECX, 0x10000000U, VENDOR_INTEL | VENDOR_AMD, "AVX instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x20000000U, VENDOR_INTEL | VENDOR_AMD, "16-bit FP conversion instructions"},
            { 0x00000001U, 0U, REG_ECX, 0x40000000U, VENDOR_INTEL | VENDOR_AMD, "RDRAND instruction"},
            { 0x00000001U, 0U, REG_ECX, 0x80000000U, VENDOR_ANY               , "RAZ (hypervisor)"},

        /*  Thermal and Power Management Feature Flags (0000_0006h) */
            { 0x00000006U, 0U, REG_EAX, 0x00000001U, VENDOR_INTEL             , "Digital temperature sensor"},
            { 0x00000006U, 0U, REG_EAX, 0x00000002U, VENDOR_INTEL             , "Intel Turbo Boost Technology"},
            { 0x00000006U, 0U, REG_EAX, 0x00000004U, VENDOR_INTEL | VENDOR_AMD, "Always running APIC timer (ARAT)"},
        /*  { 0x00000006U, 0U, REG_EAX, 0x00000008U, VENDOR_INTEL             , ""}, */   /* Reserved */
            { 0x00000006U, 0U, REG_EAX, 0x00000010U, VENDOR_INTEL             , "Power limit notification controls"},
            { 0x00000006U, 0U, REG_EAX, 0x00000020U, VENDOR_INTEL             , "Clock modulation duty cycle extensions"},
            { 0x00000006U, 0U, REG_EAX, 0x00000040U, VENDOR_INTEL             , "Package thermal management"},
            { 0x00000006U, 0U, REG_EAX, 0x00000080U, VENDOR_INTEL             , "Hardware-managed P-state base support (HWP)"},
            { 0x00000006U, 0U, REG_EAX, 0x00000100U, VENDOR_INTEL             , "HWP notification interrupt enable MSR"},
            { 0x00000006U, 0U, REG_EAX, 0x00000200U, VENDOR_INTEL             , "HWP activity window MSR"},
            { 0x00000006U, 0U, REG_EAX, 0x00000400U, VENDOR_INTEL             , "HWP energy/performance preference MSR"},
            { 0x00000006U, 0U, REG_EAX, 0x00000800U, VENDOR_INTEL             , "HWP package level request MSR"},
        /*  { 0x00000006U, 0U, REG_EAX, 0x00001000U, VENDOR_INTEL             , ""}, */   /* Reserved */
            { 0x00000006U, 0U, REG_EAX, 0x00002000U, VENDOR_INTEL             , "Hardware duty cycle programming (HDC)"},
            { 0x00000006U, 0U, REG_EAX, 0x00004000U, VENDOR_INTEL             , "Intel Turbo Boost Max Technology 3.0"},
            { 0x00000006U, 0U, REG_EAX, 0x00008000U, VENDOR_INTEL             , "HWP Capabilities, Highest Performance change"},
            { 0x00000006U, 0U, REG_EAX, 0x00010000U, VENDOR_INTEL             , "HWP PECI override"},
            { 0x00000006U, 0U, REG_EAX, 0x00020000U, VENDOR_INTEL             , "Flexible HWP"},
            { 0x00000006U, 0U, REG_EAX, 0x00040000U, VENDOR_INTEL             , "Fast access mode for IA32_HWP_REQUEST MSR"},
            { 0x00000006U, 0U, REG_EAX, 0x00080000U, VENDOR_INTEL             , "Hardware feedback MSRs"},
            { 0x00000006U, 0U, REG_EAX, 0x00100000U, VENDOR_INTEL             , "Ignoring Idle Logical Processor HWP request"},
        /*  { 0x00000006U, 0U, REG_EAX, 0x00200000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_EAX, 0x00400000U, VENDOR_INTEL             , ""}, */   /* Reserved */
            { 0x00000006U, 0U, REG_EAX, 0x00800000U, VENDOR_INTEL             , "Enhanced hardware feedback MSRs"},
        /*  { 0x00000006U, 0U, REG_EAX, 0x01000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_EAX, 0x02000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_EAX, 0x04000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_EAX, 0x08000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_EAX, 0x10000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_EAX, 0x20000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_EAX, 0x40000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
            { 0x00000006U, 0U, REG_EAX, 0x80000000U, VENDOR_INTEL             , "IP payloads are LIP"},

            { 0x00000006U, 0U, REG_ECX, 0x00000001U, VENDOR_INTEL | VENDOR_AMD, "Hardware Coordination Feedback Capability (APERF and MPERF)"},
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000002U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000004U, VENDOR_INTEL             , ""}, */   /* Reserved */
            { 0x00000006U, 0U, REG_ECX, 0x00000008U, VENDOR_INTEL             , "Performance-energy bias preference"},
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000010U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000020U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000040U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000080U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000100U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000200U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000400U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00000800U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00001000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00002000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00004000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00008000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00010000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00020000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00040000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00080000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00100000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00200000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00400000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x00800000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x01000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x02000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x04000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x08000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x10000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x20000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x40000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000006U, 0U, REG_ECX, 0x80000000U, VENDOR_INTEL             , ""}, */   /* Reserved */

        /*  Structured Extended Feature Flags (0000_0007h) */
            { 0x00000007U, 0U, REG_EBX, 0x00000001U, VENDOR_INTEL | VENDOR_AMD, "FSGSBASE instructions"},
            { 0x00000007U, 0U, REG_EBX, 0x00000002U, VENDOR_INTEL             , "IA32_TSC_ADJUST MSR supported"},
            { 0x00000007U, 0U, REG_EBX, 0x00000004U, VENDOR_INTEL             , "Software Guard Extensions (SGX)"},
            { 0x00000007U, 0U, REG_EBX, 0x00000008U, VENDOR_INTEL | VENDOR_AMD, "Bit Manipulation Instructions (BMI1)"},
            { 0x00000007U, 0U, REG_EBX, 0x00000010U, VENDOR_INTEL             , "Hardware Lock Elision (HLE)"},
            { 0x00000007U, 0U, REG_EBX, 0x00000020U, VENDOR_INTEL | VENDOR_AMD, "Advanced Vector Extensions 2.0 (AVX2)"},
            { 0x00000007U, 0U, REG_EBX, 0x00000040U, VENDOR_INTEL             , "x87 FPU data pointer updated only on x87 exceptions"},
            { 0x00000007U, 0U, REG_EBX, 0x00000080U, VENDOR_INTEL | VENDOR_AMD, "Supervisor Mode Execution Protection (SMEP)"},
            { 0x00000007U, 0U, REG_EBX, 0x00000100U, VENDOR_INTEL | VENDOR_AMD, "Bit Manipulation Instructions 2 (BMI2)"},
            { 0x00000007U, 0U, REG_EBX, 0x00000200U, VENDOR_INTEL | VENDOR_AMD, "Enhanced REP MOVSB/STOSB"}, /* Undocumented on AMD */ // NOLINT
            { 0x00000007U, 0U, REG_EBX, 0x00000400U, VENDOR_INTEL | VENDOR_AMD, "INVPCID instruction"}, /* Undocumented on AMD, but instruction documented */ // NOLINT
            { 0x00000007U, 0U, REG_EBX, 0x00000800U, VENDOR_INTEL             , "Restricted Transactional Memory (RTM)"},
            { 0x00000007U, 0U, REG_EBX, 0x00001000U, VENDOR_INTEL | VENDOR_AMD, "Platform QoS Monitoring (PQM)"},
            { 0x00000007U, 0U, REG_EBX, 0x00002000U, VENDOR_INTEL             , "x87 FPU CS and DS deprecated"},
            { 0x00000007U, 0U, REG_EBX, 0x00004000U, VENDOR_INTEL             , "Memory Protection Extensions (MPX)"},
            { 0x00000007U, 0U, REG_EBX, 0x00008000U, VENDOR_INTEL | VENDOR_AMD, "Platform QoS Enforcement (PQE)"},
            { 0x00000007U, 0U, REG_EBX, 0x00010000U, VENDOR_INTEL             , "AVX512 foundation (AVX512F)"},
            { 0x00000007U, 0U, REG_EBX, 0x00020000U, VENDOR_INTEL             , "AVX512 double/quadword instructions (AVX512DQ)"},
            { 0x00000007U, 0U, REG_EBX, 0x00040000U, VENDOR_INTEL | VENDOR_AMD, "RDSEED instruction"},
            { 0x00000007U, 0U, REG_EBX, 0x00080000U, VENDOR_INTEL | VENDOR_AMD, "Multi-Precision Add-Carry Instruction Extensions (ADX)"},
            { 0x00000007U, 0U, REG_EBX, 0x00100000U, VENDOR_INTEL | VENDOR_AMD, "Supervisor Mode Access Prevention (SMAP)"},
            { 0x00000007U, 0U, REG_EBX, 0x00200000U, VENDOR_INTEL             , "AVX512 integer FMA instructions (AVX512IFMA)"},
            { 0x00000007U, 0U, REG_EBX, 0x00400000U, VENDOR_INTEL             , "Persistent commit instruction (PCOMMIT)"},
            { 0x00000007U, 0U, REG_EBX, 0x00400000U,                VENDOR_AMD, "RDPID instruction and TSC_AUX MSR support"},
            { 0x00000007U, 0U, REG_EBX, 0x00800000U, VENDOR_INTEL | VENDOR_AMD, "CLFLUSHOPT instruction"},
            { 0x00000007U, 0U, REG_EBX, 0x01000000U, VENDOR_INTEL | VENDOR_AMD, "cache line write-back instruction (CLWB)"},
            { 0x00000007U, 0U, REG_EBX, 0x02000000U, VENDOR_INTEL             , "Intel Processor Trace"},
            { 0x00000007U, 0U, REG_EBX, 0x04000000U, VENDOR_INTEL             , "AVX512 prefetch instructions (AVX512PF)"},
            { 0x00000007U, 0U, REG_EBX, 0x08000000U, VENDOR_INTEL             , "AVX512 exponent/reciprocal instructions (AVX512ER)"},
            { 0x00000007U, 0U, REG_EBX, 0x10000000U, VENDOR_INTEL             , "AVX512 conflict detection instructions (AVX512CD)"},
            { 0x00000007U, 0U, REG_EBX, 0x20000000U, VENDOR_INTEL | VENDOR_AMD, "SHA-1/SHA-256 instructions"},
            { 0x00000007U, 0U, REG_EBX, 0x40000000U, VENDOR_INTEL             , "AVX512 byte/word instructions (AVX512BW)"},
            { 0x00000007U, 0U, REG_EBX, 0x80000000U, VENDOR_INTEL             , "AVX512 vector length extensions (AVX512VL)"},

            { 0x00000007U, 0U, REG_ECX, 0x00000001U, VENDOR_INTEL             , "PREFETCHWT1 instruction"},
            { 0x00000007U, 0U, REG_ECX, 0x00000002U, VENDOR_INTEL             , "AVX512 vector byte manipulation instructions (AVX512VBMI)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000004U, VENDOR_INTEL | VENDOR_AMD, "User Mode Instruction Prevention (UMIP)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000008U, VENDOR_INTEL | VENDOR_AMD, "Protection Keys for User-mode pages (PKU)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000010U, VENDOR_INTEL | VENDOR_AMD, "OS has enabled protection keys (OSPKE)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000020U, VENDOR_INTEL             , "Wait and Pause Enhancements (WAITPKG)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000040U, VENDOR_INTEL             , "AVX512_VBMI2"},
            { 0x00000007U, 0U, REG_ECX, 0x00000080U, VENDOR_INTEL | VENDOR_AMD, "CET shadow stack (CET_SS)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000100U, VENDOR_INTEL             , "Galois Field NI / Galois Field Affine Transformation (GFNI)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000200U, VENDOR_INTEL | VENDOR_AMD, "VEX-encoded AES-NI (VAES)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000400U, VENDOR_INTEL | VENDOR_AMD, "VEX-encoded PCLMUL (VPCL)"},
            { 0x00000007U, 0U, REG_ECX, 0x00000800U, VENDOR_INTEL             , "AVX512 Vector Neural Network Instructions (AVX512VNNI)"},
            { 0x00000007U, 0U, REG_ECX, 0x00001000U, VENDOR_INTEL             , "AVX512 Bitwise Algorithms (AVX515BITALG)"},
        /*  { 0x00000007U, 0U, REG_ECX, 0x00002000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_ECX, 0x00004000U, VENDOR_INTEL             , "AVX512 VPOPCNTDQ"},
        /*  { 0x00000007U, 0U, REG_ECX, 0x00008000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_ECX, 0x00010000U, VENDOR_INTEL             , "5-level paging (VA57)"},
        /*  { 0x00000007U, 0U, REG_ECX, 0x00020000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 0U, REG_ECX, 0x00040000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 0U, REG_ECX, 0x00080000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 0U, REG_ECX, 0x00100000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 0U, REG_ECX, 0x00200000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_ECX, 0x00400000U, VENDOR_INTEL | VENDOR_AMD, "Read Processor ID (RDPID)"},
            { 0x00000007U, 0U, REG_ECX, 0x00800000U, VENDOR_INTEL             , "Key locker (KL)"},
        /*  { 0x00000007U, 0U, REG_ECX, 0x01000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_ECX, 0x02000000U, VENDOR_INTEL             , "Cache Line Demote (CLDEMOTE)"},
        /*  { 0x00000007U, 0U, REG_ECX, 0x04000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_ECX, 0x08000000U, VENDOR_INTEL             , "32-bit Direct Stores (MOVDIRI)"},
            { 0x00000007U, 0U, REG_ECX, 0x10000000U, VENDOR_INTEL             , "64-bit Direct Stores (MOVDIRI64B)"},
            { 0x00000007U, 0U, REG_ECX, 0x20000000U, VENDOR_INTEL             , "Enqueue Stores (ENQCMD)"},
            { 0x00000007U, 0U, REG_ECX, 0x40000000U, VENDOR_INTEL             , "SGX Launch Configuration (SGX_LC)"},
            { 0x00000007U, 0U, REG_ECX, 0x80000000U, VENDOR_INTEL             , "Protection keys for supervisor-mode pages (PKS)"},

        /*  { 0x00000007U, 0U, REG_EDX, 0x00000001U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 0U, REG_EDX, 0x00000002U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_EDX, 0x00000004U, VENDOR_INTEL             , "AVX512_4VNNIW"},
            { 0x00000007U, 0U, REG_EDX, 0x00000008U, VENDOR_INTEL             , "AVX512_4FMAPS"},
            { 0x00000007U, 0U, REG_EDX, 0x00000010U, VENDOR_INTEL | VENDOR_AMD, "Fast Short REP MOV"}, /* Undocumented on AMD */ // NOLINT
        /*  { 0x00000007U, 0U, REG_EDX, 0x00000020U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 0U, REG_EDX, 0x00000040U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 0U, REG_EDX, 0x00000080U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_EDX, 0x00000100U, VENDOR_INTEL             , "AVX512_VP2INTERSECT"},
        /*  { 0x00000007U, 0U, REG_EDX, 0x00000200U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_EDX, 0x00000400U, VENDOR_INTEL             , "MD_CLEAR"},
        /*  { 0x00000007U, 0U, REG_EDX, 0x00000800U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 0U, REG_EDX, 0x00001000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_EDX, 0x00002000U, VENDOR_INTEL             , "TSX Force Abort MSR"},
            { 0x00000007U, 0U, REG_EDX, 0x00004000U, VENDOR_INTEL             , "SERIALIZE"},
            { 0x00000007U, 0U, REG_EDX, 0x00008000U, VENDOR_INTEL             , "Hybrid"},
            { 0x00000007U, 0U, REG_EDX, 0x00010000U, VENDOR_INTEL             , "TSX suspend load address tracking"},
        /*  { 0x00000007U, 0U, REG_EDX, 0x00020000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_EDX, 0x00040000U, VENDOR_INTEL             , "PCONFIG"},
        /*  { 0x00000007U, 0U, REG_EDX, 0x00080000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_EDX, 0x00100000U, VENDOR_INTEL             , "CET indirect branch tracking (CET_IBT)"},
        /*  { 0x00000007U, 0U, REG_EDX, 0x00200000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 0U, REG_EDX, 0x00400000U, VENDOR_INTEL             , "Tile computation on bfloat16 (AMX-BF16)"},
            { 0x00000007U, 0U, REG_EDX, 0x00800000U, VENDOR_INTEL             , "AVX512 FP16"},
            { 0x00000007U, 0U, REG_EDX, 0x01000000U, VENDOR_INTEL             , "Tile architecture (AMX-TILE)"},
            { 0x00000007U, 0U, REG_EDX, 0x02000000U, VENDOR_INTEL             , "Tile computation on 8-bit integers (AMX-INT8)"},
            { 0x00000007U, 0U, REG_EDX, 0x04000000U, VENDOR_INTEL             , "Speculation Control (IBRS and IBPB)"},
            { 0x00000007U, 0U, REG_EDX, 0x08000000U, VENDOR_INTEL             , "Single Thread Indirect Branch Predictors (STIBP)"},
            { 0x00000007U, 0U, REG_EDX, 0x10000000U, VENDOR_INTEL             , "L1 Data Cache (L1D) Flush"},
            { 0x00000007U, 0U, REG_EDX, 0x20000000U, VENDOR_INTEL             , "IA32_ARCH_CAPABILITIES MSR"},
            { 0x00000007U, 0U, REG_EDX, 0x40000000U, VENDOR_INTEL             , "IA32_CORE_CAPABILITIES MSR"},
            { 0x00000007U, 0U, REG_EDX, 0x80000000U, VENDOR_INTEL             , "Speculative Store Bypass Disable (SSBD)"},

        /*  { 0x00000007U, 1U, REG_EAX, 0x00000001U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00000002U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00000004U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00000008U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 1U, REG_EAX, 0x00000010U, VENDOR_INTEL             , "AVX Vector Neural Network Instructions (AVX-VNNI)"},
            { 0x00000007U, 1U, REG_EAX, 0x00000020U, VENDOR_INTEL             , "Vector Neural Network BFLOAT16 (AVX512_BF16)"},
        /*  { 0x00000007U, 1U, REG_EAX, 0x00000040U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00000080U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00000100U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00000200U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 1U, REG_EAX, 0x00000400U, VENDOR_INTEL             , "Fast zero-length MOVSB"},
            { 0x00000007U, 1U, REG_EAX, 0x00000800U, VENDOR_INTEL             , "Fast short STOSB"},
            { 0x00000007U, 1U, REG_EAX, 0x00001000U, VENDOR_INTEL             , "Fast short CMPSB, SCASB"},
        /*  { 0x00000007U, 1U, REG_EAX, 0x00002000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00004000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00008000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00010000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00020000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00040000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00080000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00100000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x00200000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 1U, REG_EAX, 0x00400000U, VENDOR_INTEL             , "History reset (HRESET)"},
        /*  { 0x00000007U, 1U, REG_EAX, 0x00800000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x01000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x02000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x00000007U, 1U, REG_EAX, 0x04000000U, VENDOR_INTEL             , "Linear Address Masking (LAM)"},
        /*  { 0x00000007U, 1U, REG_EAX, 0x08000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x10000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x20000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x40000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x00000007U, 1U, REG_EAX, 0x80000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */

        /*  Processor Trace Enumeration (0000_0014h) */
            { 0x00000014U, 0U, REG_EBX, 0x00000001U, VENDOR_INTEL             , "CR3 filtering"},
            { 0x00000014U, 0U, REG_EBX, 0x00000002U, VENDOR_INTEL             , "Configurable PSB, Cycle-Accurate Mode"},
            { 0x00000014U, 0U, REG_EBX, 0x00000004U, VENDOR_INTEL             , "Filtering preserved across warm reset"},
            { 0x00000014U, 0U, REG_EBX, 0x00000008U, VENDOR_INTEL             , "MTC timing packet, suppression of COFI-based packets"},
            { 0x00000014U, 0U, REG_EBX, 0x00000010U, VENDOR_INTEL             , "PTWRITE"},
            { 0x00000014U, 0U, REG_EBX, 0x00000020U, VENDOR_INTEL             , "Power Event Trace"},
            { 0x00000014U, 0U, REG_EBX, 0x00000040U, VENDOR_INTEL             , "PSB and PMI preservation MSRs"},
        /*  { 0x00000014U, 0U, REG_EBX, 0x00000080U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00000100U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00000200U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00000400U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00000800U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00001000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00002000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00004000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00008000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00010000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00020000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00040000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00080000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00100000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00200000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00400000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x00800000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x01000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x02000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x04000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x08000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x10000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x20000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x40000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_EBX, 0x80000000U, VENDOR_INTEL             , ""}, */   /* Reserved */

            { 0x00000014U, 0U, REG_ECX, 0x00000001U, VENDOR_INTEL             , "ToPA output scheme"},
            { 0x00000014U, 0U, REG_ECX, 0x00000002U, VENDOR_INTEL             , "ToPA tables hold multiple output entries"},
            { 0x00000014U, 0U, REG_ECX, 0x00000004U, VENDOR_INTEL             , "Single-range output scheme"},
            { 0x00000014U, 0U, REG_ECX, 0x00000008U, VENDOR_INTEL             , "Trace Transport output support"},
        /*  { 0x00000014U, 0U, REG_ECX, 0x00000010U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00000020U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00000040U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00000080U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00000100U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00000200U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00000400U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00000800U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00001000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00002000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00004000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00008000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00010000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00020000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00040000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00080000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00100000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00200000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00400000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x00800000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x01000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x02000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x04000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x08000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x10000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x20000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
        /*  { 0x00000014U, 0U, REG_ECX, 0x40000000U, VENDOR_INTEL             , ""}, */   /* Reserved */
            { 0x00000014U, 0U, REG_ECX, 0x80000000U, VENDOR_INTEL             , "IP payloads are LIP"},

        /*  Hypervisor (4000_0001h) */
            { 0x40000001U, 0U, REG_EAX, 0x00000001U, VENDOR_HV_KVM            , "Clocksource"},
            { 0x40000001U, 0U, REG_EAX, 0x00000002U, VENDOR_HV_KVM            , "NOP IO Delay"},
            { 0x40000001U, 0U, REG_EAX, 0x00000004U, VENDOR_HV_KVM            , "MMU Op"},
            { 0x40000001U, 0U, REG_EAX, 0x00000008U, VENDOR_HV_KVM            , "Clocksource 2"},
            { 0x40000001U, 0U, REG_EAX, 0x00000010U, VENDOR_HV_KVM            , "Async PF"},
            { 0x40000001U, 0U, REG_EAX, 0x00000020U, VENDOR_HV_KVM            , "Steal Time"},
            { 0x40000001U, 0U, REG_EAX, 0x00000040U, VENDOR_HV_KVM            , "PV EOI"},
            { 0x40000001U, 0U, REG_EAX, 0x00000080U, VENDOR_HV_KVM            , "PV UNHALT"},
        /*  { 0x40000001U, 0U, REG_EAX, 0x00000100U,                          , ""}, */   /* Reserved */
            { 0x40000001U, 0U, REG_EAX, 0x00000200U, VENDOR_HV_KVM            , "PV TLB FLUSH"},
            { 0x40000001U, 0U, REG_EAX, 0x00000400U, VENDOR_HV_KVM            , "PV ASYNC PF VMEXIT"},
            { 0x40000001U, 0U, REG_EAX, 0x00000800U, VENDOR_HV_KVM            , "PV SEND IPI"},
            { 0x40000001U, 0U, REG_EAX, 0x00001000U, VENDOR_HV_KVM            , "PV POLL CONTROL"},
            { 0x40000001U, 0U, REG_EAX, 0x00002000U, VENDOR_HV_KVM            , "PV SCHED YIELD"},
        /*  { 0x40000001U, 0U, REG_EAX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00010000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00020000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x00800000U,                          , ""}, */   /* Reserved */
            { 0x40000001U, 0U, REG_EAX, 0x01000000U, VENDOR_HV_KVM            , "Clocksource Stable"},
        /*  { 0x40000001U, 0U, REG_EAX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000001U, 0U, REG_EAX, 0x80000000U,                          , ""}, */   /* Reserved */

        /*  Hypervisor (4000_0003h) */
            { 0x40000003U, 0U, REG_EAX, 0x00000001U, VENDOR_HV_HYPERV         , "VP_RUNTIME"},
            { 0x40000003U, 0U, REG_EAX, 0x00000002U, VENDOR_HV_HYPERV         , "TIME_REF_COUNT"},
            { 0x40000003U, 0U, REG_EAX, 0x00000004U, VENDOR_HV_HYPERV         , "Basic SynIC MSRs"},
            { 0x40000003U, 0U, REG_EAX, 0x00000008U, VENDOR_HV_HYPERV         , "Synthetic Timer"},
            { 0x40000003U, 0U, REG_EAX, 0x00000010U, VENDOR_HV_HYPERV         , "APIC access"},
            { 0x40000003U, 0U, REG_EAX, 0x00000020U, VENDOR_HV_HYPERV         , "Hypercall MSRs"},
            { 0x40000003U, 0U, REG_EAX, 0x00000040U, VENDOR_HV_HYPERV         , "VP Index MSR"},
            { 0x40000003U, 0U, REG_EAX, 0x00000080U, VENDOR_HV_HYPERV         , "System Reset MSR"},
            { 0x40000003U, 0U, REG_EAX, 0x00000100U, VENDOR_HV_HYPERV         , "Access stats MSRs"},
            { 0x40000003U, 0U, REG_EAX, 0x00000200U, VENDOR_HV_HYPERV         , "Reference TSC"},
            { 0x40000003U, 0U, REG_EAX, 0x00000400U, VENDOR_HV_HYPERV         , "Guest Idle MSR"},
            { 0x40000003U, 0U, REG_EAX, 0x00000800U, VENDOR_HV_HYPERV         , "Timer Frequency MSRs"},
            { 0x40000003U, 0U, REG_EAX, 0x00001000U, VENDOR_HV_HYPERV         , "Debug MSRs"},
            { 0x40000003U, 0U, REG_EAX, 0x00002000U, VENDOR_HV_HYPERV         , "Reenlightenment controls"},
        /*  { 0x40000003U, 0U, REG_EAX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00010000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00020000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EAX, 0x80000000U,                          , ""}, */   /* Reserved */

            { 0x40000003U, 0U, REG_EBX, 0x00000001U, VENDOR_HV_HYPERV         , "CreatePartitions"},
            { 0x40000003U, 0U, REG_EBX, 0x00000002U, VENDOR_HV_HYPERV         , "AccessPartitionId"},
            { 0x40000003U, 0U, REG_EBX, 0x00000004U, VENDOR_HV_HYPERV         , "AccessMemoryPool"},
            { 0x40000003U, 0U, REG_EBX, 0x00000008U, VENDOR_HV_HYPERV         , "AdjustMemoryBuffers"},
            { 0x40000003U, 0U, REG_EBX, 0x00000010U, VENDOR_HV_HYPERV         , "PostMessages"},
            { 0x40000003U, 0U, REG_EBX, 0x00000020U, VENDOR_HV_HYPERV         , "SignalEvents"},
            { 0x40000003U, 0U, REG_EBX, 0x00000040U, VENDOR_HV_HYPERV         , "CreatePort"},
            { 0x40000003U, 0U, REG_EBX, 0x00000080U, VENDOR_HV_HYPERV         , "ConnectPort"},
            { 0x40000003U, 0U, REG_EBX, 0x00000100U, VENDOR_HV_HYPERV         , "AccessStats"},
        /*  { 0x40000003U, 0U, REG_EBX, 0x00000200U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x00000400U,                          , ""}, */   /* Reserved */
            { 0x40000003U, 0U, REG_EBX, 0x00000800U, VENDOR_HV_HYPERV         , "Debugging"},
            { 0x40000003U, 0U, REG_EBX, 0x00001000U, VENDOR_HV_HYPERV         , "CpuManagement"},
            { 0x40000003U, 0U, REG_EBX, 0x00002000U, VENDOR_HV_HYPERV         , "ConfigureProfiler"},
            { 0x40000003U, 0U, REG_EBX, 0x00004000U, VENDOR_HV_HYPERV         , "EnableExpandedStackwalking"},
        /*  { 0x40000003U, 0U, REG_EBX, 0x00008000U,                          , ""}, */   /* Reserved */
            { 0x40000003U, 0U, REG_EBX, 0x00010000U, VENDOR_HV_HYPERV         , "AccessVSM"},
            { 0x40000003U, 0U, REG_EBX, 0x00020000U, VENDOR_HV_HYPERV         , "AccessVpRegisters"},
        /*  { 0x40000003U, 0U, REG_EBX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x00080000U,                          , ""}, */   /* Reserved */
            { 0x40000003U, 0U, REG_EBX, 0x00100000U, VENDOR_HV_HYPERV         , "EnableExtendedHypercalls"},
            { 0x40000003U, 0U, REG_EBX, 0x00200000U, VENDOR_HV_HYPERV         , "StartVirtualProcessor"},
        /*  { 0x40000003U, 0U, REG_EBX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EBX, 0x80000000U,                          , ""}, */   /* Reserved */

            { 0x40000003U, 0U, REG_EDX, 0x00000001U, VENDOR_HV_HYPERV         , "MWAIT instruction support (deprecated)"},
            { 0x40000003U, 0U, REG_EDX, 0x00000002U, VENDOR_HV_HYPERV         , "Guest debugging support"},
            { 0x40000003U, 0U, REG_EDX, 0x00000004U, VENDOR_HV_HYPERV         , "Performance Monitor support"},
            { 0x40000003U, 0U, REG_EDX, 0x00000008U, VENDOR_HV_HYPERV         , "Physical CPU dynamic partitioning event support"},
            { 0x40000003U, 0U, REG_EDX, 0x00000010U, VENDOR_HV_HYPERV         , "Hypercall input params via XMM registers"},
            { 0x40000003U, 0U, REG_EDX, 0x00000020U, VENDOR_HV_HYPERV         , "Virtual guest idle state support"},
            { 0x40000003U, 0U, REG_EDX, 0x00000040U, VENDOR_HV_HYPERV         , "Hypervisor sleep state support"},
            { 0x40000003U, 0U, REG_EDX, 0x00000080U, VENDOR_HV_HYPERV         , "NUMA distance query support"},
            { 0x40000003U, 0U, REG_EDX, 0x00000100U, VENDOR_HV_HYPERV         , "Timer frequency details available"},
            { 0x40000003U, 0U, REG_EDX, 0x00000200U, VENDOR_HV_HYPERV         , "Synthetic machine check injection support"},
            { 0x40000003U, 0U, REG_EDX, 0x00000400U, VENDOR_HV_HYPERV         , "Guest crash MSR support"},
            { 0x40000003U, 0U, REG_EDX, 0x00000800U, VENDOR_HV_HYPERV         , "Debug MSR support"},
            { 0x40000003U, 0U, REG_EDX, 0x00001000U, VENDOR_HV_HYPERV         , "NPIEP support"},
            { 0x40000003U, 0U, REG_EDX, 0x00002000U, VENDOR_HV_HYPERV         , "Hypervisor disable support"},
            { 0x40000003U, 0U, REG_EDX, 0x00004000U, VENDOR_HV_HYPERV         , "Extended GVA ranges for flush virtual address list available"},
            { 0x40000003U, 0U, REG_EDX, 0x00008000U, VENDOR_HV_HYPERV         , "Hypercall output via XMM registers"},
            { 0x40000003U, 0U, REG_EDX, 0x00010000U, VENDOR_HV_HYPERV         , "Virtual guest idle state"},
            { 0x40000003U, 0U, REG_EDX, 0x00020000U, VENDOR_HV_HYPERV         , "Soft interrupt polling mode available"},
            { 0x40000003U, 0U, REG_EDX, 0x00040000U, VENDOR_HV_HYPERV         , "Hypercall MSR lock available"},
            { 0x40000003U, 0U, REG_EDX, 0x00080000U, VENDOR_HV_HYPERV         , "Direct synthetic timers support"},
            { 0x40000003U, 0U, REG_EDX, 0x00100000U, VENDOR_HV_HYPERV         , "PAT register available for VSM"},
            { 0x40000003U, 0U, REG_EDX, 0x00200000U, VENDOR_HV_HYPERV         , "bndcfgs register available for VSM"},
        /*  { 0x40000003U, 0U, REG_EDX, 0x00400000U,                          , ""}, */   /* Reserved */
            { 0x40000003U, 0U, REG_EDX, 0x00800000U, VENDOR_HV_HYPERV         , "Synthetic time unhalted timer"},
        /*  { 0x40000003U, 0U, REG_EDX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EDX, 0x02000000U,                          , ""}, */   /* Reserved */
            { 0x40000003U, 0U, REG_EDX, 0x04000000U, VENDOR_HV_HYPERV         , "Intel Last Branch Record (LBR) feature"},
        /*  { 0x40000003U, 0U, REG_EDX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EDX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EDX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EDX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000003U, 0U, REG_EDX, 0x80000000U,                          , ""}, */   /* Reserved */

        /*  Hypervisor implementation recommendations (4000_0004h) */
            { 0x40000004U, 0U, REG_EAX, 0x00000001U, VENDOR_HV_HYPERV         , "Hypercall for address space switches"},
            { 0x40000004U, 0U, REG_EAX, 0x00000002U, VENDOR_HV_HYPERV         , "Hypercall for local TLB flushes"},
            { 0x40000004U, 0U, REG_EAX, 0x00000004U, VENDOR_HV_HYPERV         , "Hypercall for remote TLB flushes"},
            { 0x40000004U, 0U, REG_EAX, 0x00000008U, VENDOR_HV_HYPERV         , "MSRs for accessing APIC registers"},
            { 0x40000004U, 0U, REG_EAX, 0x00000010U, VENDOR_HV_HYPERV         , "Hypervisor MSR for system RESET"},
            { 0x40000004U, 0U, REG_EAX, 0x00000020U, VENDOR_HV_HYPERV         , "Relaxed timing"},
            { 0x40000004U, 0U, REG_EAX, 0x00000040U, VENDOR_HV_HYPERV         , "DMA remapping"},
            { 0x40000004U, 0U, REG_EAX, 0x00000080U, VENDOR_HV_HYPERV         , "Interrupt remapping"},
            { 0x40000004U, 0U, REG_EAX, 0x00000100U, VENDOR_HV_HYPERV         , "x2APIC MSRs"},
            { 0x40000004U, 0U, REG_EAX, 0x00000200U, VENDOR_HV_HYPERV         , "Deprecating AutoEOI"},
            { 0x40000004U, 0U, REG_EAX, 0x00000400U, VENDOR_HV_HYPERV         , "Hypercall for SyntheticClusterIpi"},
            { 0x40000004U, 0U, REG_EAX, 0x00000800U, VENDOR_HV_HYPERV         , "Interface ExProcessorMasks"},
            { 0x40000004U, 0U, REG_EAX, 0x00001000U, VENDOR_HV_HYPERV         , "Nested Hyper-V partition"},
            { 0x40000004U, 0U, REG_EAX, 0x00002000U, VENDOR_HV_HYPERV         , "INT for MBEC system calls"},
            { 0x40000004U, 0U, REG_EAX, 0x00004000U, VENDOR_HV_HYPERV         , "Enlightenment VMCS interface"},
            { 0x40000004U, 0U, REG_EAX, 0x00008000U, VENDOR_HV_HYPERV         , "Synced timeline"},
        /*  { 0x40000004U, 0U, REG_EAX, 0x00010000U,                          , ""}, */   /* Reserved */
            { 0x40000004U, 0U, REG_EAX, 0x00020000U, VENDOR_HV_HYPERV         , "Direct local flush entire"},
            { 0x40000004U, 0U, REG_EAX, 0x00040000U, VENDOR_HV_HYPERV         , "No architectural core sharing"},
        /*  { 0x40000004U, 0U, REG_EAX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000004U, 0U, REG_EAX, 0x80000000U,                          , ""}, */   /* Reserved */

        /*  Hypervisor hardware features enabled (4000_0006h) */
            { 0x40000006U, 0U, REG_EAX, 0x00000001U, VENDOR_HV_HYPERV         , "APIC overlay assist"},
            { 0x40000006U, 0U, REG_EAX, 0x00000002U, VENDOR_HV_HYPERV         , "MSR bitmaps"},
            { 0x40000006U, 0U, REG_EAX, 0x00000004U, VENDOR_HV_HYPERV         , "Architectural performance counters"},
            { 0x40000006U, 0U, REG_EAX, 0x00000008U, VENDOR_HV_HYPERV         , "Second-level address translation"},
            { 0x40000006U, 0U, REG_EAX, 0x00000010U, VENDOR_HV_HYPERV         , "DMA remapping"},
            { 0x40000006U, 0U, REG_EAX, 0x00000020U, VENDOR_HV_HYPERV         , "Interrupt remapping"},
            { 0x40000006U, 0U, REG_EAX, 0x00000040U, VENDOR_HV_HYPERV         , "Memory patrol scrubber"},
            { 0x40000006U, 0U, REG_EAX, 0x00000080U, VENDOR_HV_HYPERV         , "DMA protection"},
            { 0x40000006U, 0U, REG_EAX, 0x00000100U, VENDOR_HV_HYPERV         , "HPET"},
            { 0x40000006U, 0U, REG_EAX, 0x00000200U, VENDOR_HV_HYPERV         , "Volatile synthetic timers"},
        /*  { 0x40000006U, 0U, REG_EAX, 0x00000400U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00000800U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00001000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00002000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00010000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00020000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000006U, 0U, REG_EAX, 0x80000000U,                          , ""}, */   /* Reserved */

        /*  Hypervisor CPU management features (4000_0007h) */
            { 0x40000007U, 0U, REG_EAX, 0x00000001U, VENDOR_HV_HYPERV         , "Start logical processor"},
            { 0x40000007U, 0U, REG_EAX, 0x00000002U, VENDOR_HV_HYPERV         , "Create root virtual processor"},
            { 0x40000007U, 0U, REG_EAX, 0x00000004U, VENDOR_HV_HYPERV         , "Performance counter sync"},
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000008U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000010U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000020U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000040U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000080U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000100U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000200U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000400U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00000800U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00001000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00002000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00010000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00020000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EAX, 0x80000000U,                          , ""}, */   /* ReservedIdentityBit */

            { 0x40000007U, 0U, REG_EBX, 0x00000001U, VENDOR_HV_HYPERV         , "Processor power management"},
            { 0x40000007U, 0U, REG_EBX, 0x00000002U, VENDOR_HV_HYPERV         , "MWAIT idle states"},
            { 0x40000007U, 0U, REG_EBX, 0x00000004U, VENDOR_HV_HYPERV         , "Logical processor idling"},
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000008U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000010U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000020U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000040U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000080U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000100U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000200U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000400U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00000800U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00001000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00002000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00010000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00020000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_EBX, 0x80000000U,                          , ""}, */   /* Reserved */

            { 0x40000007U, 0U, REG_ECX, 0x00000001U, VENDOR_HV_HYPERV         , "Remap guest uncached"},
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000002U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000004U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000008U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000010U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000020U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000040U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000080U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000100U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000200U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000400U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00000800U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00001000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00002000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00010000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00020000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000007U, 0U, REG_ECX, 0x80000000U,                          , ""}, */   /* Reserved */

        /*  Hypervisor shared virtual memory (SVM) features (4000_0008h) */
            { 0x40000008U, 0U, REG_EAX, 0x00000001U, VENDOR_HV_HYPERV         , "Shared virtual memory (SVM)"},
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000002U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000004U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000008U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000010U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000020U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000040U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000080U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000100U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000200U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000400U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00000800U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00001000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00002000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00010000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00020000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000008U, 0U, REG_EAX, 0x80000000U,                          , ""}, */   /* Reserved */

        /*  Nested hypervisor feature indentification (4000_0009h) */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00000001U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00000002U,                          , ""}, */   /* Reserved */
            { 0x40000009U, 0U, REG_EAX, 0x00000004U, VENDOR_HV_HYPERV         , "Synthetic Timer"},
        /*  { 0x40000009U, 0U, REG_EAX, 0x00000008U,                          , ""}, */   /* Reserved */
            { 0x40000009U, 0U, REG_EAX, 0x00000010U, VENDOR_HV_HYPERV         , "Interrupt control registers"},
            { 0x40000009U, 0U, REG_EAX, 0x00000020U, VENDOR_HV_HYPERV         , "Hypercall MSRs"},
            { 0x40000009U, 0U, REG_EAX, 0x00000040U, VENDOR_HV_HYPERV         , "VP index MSR"},
        /*  { 0x40000009U, 0U, REG_EAX, 0x00000080U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00000100U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00000200U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00000400U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00000800U,                          , ""}, */   /* Reserved */
            { 0x40000009U, 0U, REG_EAX, 0x00001000U, VENDOR_HV_HYPERV         , "Reenlightenment controls"},
        /*  { 0x40000009U, 0U, REG_EAX, 0x00002000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00010000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00020000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EAX, 0x80000000U,                          , ""}, */   /* Reserved */

        /*  { 0x40000009U, 0U, REG_EDX, 0x00000001U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000002U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000004U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000008U,                          , ""}, */   /* Reserved */
            { 0x40000009U, 0U, REG_EDX, 0x00000010U, VENDOR_HV_HYPERV         , "Hypercall input params via XMM registers"},
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000020U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000040U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000080U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000100U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000200U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000400U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00000800U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00001000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00002000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00004000U,                          , ""}, */   /* Reserved */
            { 0x40000009U, 0U, REG_EDX, 0x00008000U, VENDOR_HV_HYPERV         , "Hypercall output via XMM registers"},
        /*  { 0x40000009U, 0U, REG_EDX, 0x00010000U,                          , ""}, */   /* Reserved */
            { 0x40000009U, 0U, REG_EDX, 0x00020000U, VENDOR_HV_HYPERV         , "Soft interrupt polling mode available"},
        /*  { 0x40000009U, 0U, REG_EDX, 0x00040000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00080000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00100000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x40000009U, 0U, REG_EDX, 0x80000000U,                          , ""}, */   /* Reserved */

        /*  Nested hypervisor feature indentification (4000_000Ah) */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000001U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000002U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000004U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000008U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000010U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000020U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000040U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000080U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000100U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000200U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000400U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00000800U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00001000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00002000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00004000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00008000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00010000U,                          , ""}, */   /* Reserved */
            { 0x4000000AU, 0U, REG_EAX, 0x00020000U, VENDOR_HV_HYPERV         , "Direct virtual flush hypercalls"},
            { 0x4000000AU, 0U, REG_EAX, 0x00040000U, VENDOR_HV_HYPERV         , "Flush GPA space and list hypercalls"},
            { 0x4000000AU, 0U, REG_EAX, 0x00080000U, VENDOR_HV_HYPERV         , "Enlightened MSR bitmaps"},
            { 0x4000000AU, 0U, REG_EAX, 0x00100000U, VENDOR_HV_HYPERV         , "Combining virtualization exceptions in page fault exception class"},
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00200000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00400000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x00800000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x01000000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x02000000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x04000000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x08000000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x10000000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x20000000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x40000000U,                          , ""}, */   /* Reserved */
        /*  { 0x4000000AU, 0U, REG_EAX, 0x80000000U,                          , ""}, */   /* Reserved */


        /*  Extended (8000_0001h) */
            { 0x80000001U, 0U, REG_EDX, 0x00000001U,                VENDOR_AMD, "x87 FPU on chip"},
            { 0x80000001U, 0U, REG_EDX, 0x00000002U,                VENDOR_AMD, "virtual-8086 mode enhancement"},
            { 0x80000001U, 0U, REG_EDX, 0x00000004U,                VENDOR_AMD, "debugging extensions"},
            { 0x80000001U, 0U, REG_EDX, 0x00000008U,                VENDOR_AMD, "page size extensions"},
            { 0x80000001U, 0U, REG_EDX, 0x00000010U,                VENDOR_AMD, "time stamp counter"},
            { 0x80000001U, 0U, REG_EDX, 0x00000020U,                VENDOR_AMD, "AMD model-specific registers"},
            { 0x80000001U, 0U, REG_EDX, 0x00000040U,                VENDOR_AMD, "physical address extensions"},
            { 0x80000001U, 0U, REG_EDX, 0x00000080U,                VENDOR_AMD, "machine check exception"},
            { 0x80000001U, 0U, REG_EDX, 0x00000100U,                VENDOR_AMD, "CMPXCHG8B instruction"},
            { 0x80000001U, 0U, REG_EDX, 0x00000200U,                VENDOR_AMD, "APIC on chip"},
        /*  { 0x80000001U, 0U, REG_EDX, 0x00000400U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000001U, 0U, REG_EDX, 0x00000800U, VENDOR_INTEL             , "SYSENTER and SYSEXIT instructions"},
            { 0x80000001U, 0U, REG_EDX, 0x00000800U,                VENDOR_AMD, "SYSCALL and SYSRET instructions"},
            { 0x80000001U, 0U, REG_EDX, 0x00001000U,                VENDOR_AMD, "memory type range registers"},
            { 0x80000001U, 0U, REG_EDX, 0x00002000U,                VENDOR_AMD, "PTE global bit"},
            { 0x80000001U, 0U, REG_EDX, 0x00004000U,                VENDOR_AMD, "machine check architecture"},
            { 0x80000001U, 0U, REG_EDX, 0x00008000U,                VENDOR_AMD, "conditional move instruction"},
            { 0x80000001U, 0U, REG_EDX, 0x00010000U,                VENDOR_AMD, "page attribute table"},
            { 0x80000001U, 0U, REG_EDX, 0x00020000U,                VENDOR_AMD, "36-bit page size extension"},
        /*  { 0x80000001U, 0U, REG_EDX, 0x00040000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x80000001U, 0U, REG_EDX, 0x00080000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000001U, 0U, REG_EDX, 0x00100000U, VENDOR_INTEL             , "XD bit"},
            { 0x80000001U, 0U, REG_EDX, 0x00100000U,                VENDOR_AMD, "NX bit"},
        /*  { 0x80000001U, 0U, REG_EDX, 0x00200000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000001U, 0U, REG_EDX, 0x00400000U,                VENDOR_AMD, "MMX extended"},
            { 0x80000001U, 0U, REG_EDX, 0x00800000U,                VENDOR_AMD, "MMX instructions"},
            { 0x80000001U, 0U, REG_EDX, 0x01000000U,                VENDOR_AMD, "FXSAVE/FXRSTOR instructions"},
            { 0x80000001U, 0U, REG_EDX, 0x02000000U,                VENDOR_AMD, "fast FXSAVE/FXRSTOR"},
            { 0x80000001U, 0U, REG_EDX, 0x04000000U, VENDOR_INTEL | VENDOR_AMD, "1GB page support"},
            { 0x80000001U, 0U, REG_EDX, 0x08000000U, VENDOR_INTEL | VENDOR_AMD, "RDTSCP instruction"},
        /*  { 0x80000001U, 0U, REG_EDX, 0x10000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000001U, 0U, REG_EDX, 0x20000000U, VENDOR_INTEL | VENDOR_AMD, "long mode (EM64T)"},
            { 0x80000001U, 0U, REG_EDX, 0x40000000U,                VENDOR_AMD, "3DNow! extended"},
            { 0x80000001U, 0U, REG_EDX, 0x80000000U,                VENDOR_AMD, "3DNow! instructions"},

            { 0x80000001U, 0U, REG_ECX, 0x00000001U, VENDOR_INTEL | VENDOR_AMD, "LAHF/SAHF supported in 64-bit mode"},
            { 0x80000001U, 0U, REG_ECX, 0x00000002U,                VENDOR_AMD, "core multi-processing legacy mode"},
            { 0x80000001U, 0U, REG_ECX, 0x00000004U,                VENDOR_AMD, "secure virtual machine (SVM)"},
            { 0x80000001U, 0U, REG_ECX, 0x00000008U,                VENDOR_AMD, "extended APIC space"},
            { 0x80000001U, 0U, REG_ECX, 0x00000010U,                VENDOR_AMD, "AltMovCr8"},
            { 0x80000001U, 0U, REG_ECX, 0x00000020U, VENDOR_INTEL | VENDOR_AMD, "LZCNT instruction"},
            { 0x80000001U, 0U, REG_ECX, 0x00000040U,                VENDOR_AMD, "SSE4A instructions"},
            { 0x80000001U, 0U, REG_ECX, 0x00000080U,                VENDOR_AMD, "mis-aligned SSE support"},
            { 0x80000001U, 0U, REG_ECX, 0x00000100U, VENDOR_INTEL | VENDOR_AMD, "3DNow! prefetch instructions"},
            { 0x80000001U, 0U, REG_ECX, 0x00000200U,                VENDOR_AMD, "os-visible workaround (OSVW)"},
            { 0x80000001U, 0U, REG_ECX, 0x00000400U,                VENDOR_AMD, "instruction-based sampling (IBS)"},
            { 0x80000001U, 0U, REG_ECX, 0x00000800U,                VENDOR_AMD, "extended operation (XOP)"},
            { 0x80000001U, 0U, REG_ECX, 0x00001000U,                VENDOR_AMD, "SKINIT/STGI instructions"},
            { 0x80000001U, 0U, REG_ECX, 0x00002000U,                VENDOR_AMD, "watchdog timer (WDT)"},
        /*  { 0x80000001U, 0U, REG_ECX, 0x00004000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000001U, 0U, REG_ECX, 0x00008000U,                VENDOR_AMD, "lightweight profiling (LWP)"},
            { 0x80000001U, 0U, REG_ECX, 0x00010000U,                VENDOR_AMD, "4-operand FMA instructions (FMA4)"},
            { 0x80000001U, 0U, REG_ECX, 0x00020000U,                VENDOR_AMD, "Translation cache extension (TCE)"},
        /*  { 0x80000001U, 0U, REG_ECX, 0x00040000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000001U, 0U, REG_ECX, 0x00080000U,                VENDOR_AMD, "node ID support"},
        /*  { 0x80000001U, 0U, REG_ECX, 0x00100000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000001U, 0U, REG_ECX, 0x00200000U,                VENDOR_AMD, "trailing bit manipulation instructions"},
            { 0x80000001U, 0U, REG_ECX, 0x00400000U,                VENDOR_AMD, "topology extensions"},
            { 0x80000001U, 0U, REG_ECX, 0x00800000U,                VENDOR_AMD, "processor performance counter extensions"},
            { 0x80000001U, 0U, REG_ECX, 0x01000000U,                VENDOR_AMD, "NB performance counter extensions"},
            { 0x80000001U, 0U, REG_ECX, 0x02000000U,                VENDOR_AMD, "streaming performance monitor architecture"},
            { 0x80000001U, 0U, REG_ECX, 0x04000000U,                VENDOR_AMD, "data access breakpoint extension"},
            { 0x80000001U, 0U, REG_ECX, 0x08000000U,                VENDOR_AMD, "performance timestamp counter"},
            { 0x80000001U, 0U, REG_ECX, 0x10000000U,                VENDOR_AMD, "performance counter extensions"},
            { 0x80000001U, 0U, REG_ECX, 0x20000000U,                VENDOR_AMD, "MONITORX/MWAITX instructions"},
            { 0x80000001U, 0U, REG_ECX, 0x40000000U,                VENDOR_AMD, "address mask extension for instruction breakpoint"},
        /*  { 0x80000001U, 0U, REG_ECX, 0x80000000U, VENDOR_INTEL | VENDOR_AMD, ""}, */   /* Reserved */

        /*  RAS Capabilities (8000_0007h) */
            { 0x80000007U, 0U, REG_EBX, 0x00000001U,                VENDOR_AMD, "MCA overflow recovery"},
            { 0x80000007U, 0U, REG_EBX, 0x00000002U,                VENDOR_AMD, "Software uncorrectable error containment and recovery"},
            { 0x80000007U, 0U, REG_EBX, 0x00000004U,                VENDOR_AMD, "Hardware assert (HWA)"},
            { 0x80000007U, 0U, REG_EBX, 0x00000008U,                VENDOR_AMD, "Scalable MCA"},
            { 0x80000007U, 0U, REG_EBX, 0x00000010U,                VENDOR_AMD, "Platform First Error Handling (PFEH)"},

        /*  Advanced Power UManagement information (8000_0007h) */
            { 0x80000007U, 0U, REG_EDX, 0x00000001U,                VENDOR_AMD, "Temperature Sensor"},
            { 0x80000007U, 0U, REG_EDX, 0x00000002U,                VENDOR_AMD, "Frequency ID Control"},
            { 0x80000007U, 0U, REG_EDX, 0x00000004U,                VENDOR_AMD, "Voltage ID Control"},
            { 0x80000007U, 0U, REG_EDX, 0x00000008U,                VENDOR_AMD, "THERMTRIP"},
            { 0x80000007U, 0U, REG_EDX, 0x00000010U,                VENDOR_AMD, "Hardware thermal control"},
        /*  { 0x80000007U, 0U, REG_EDX, 0x00000020U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000007U, 0U, REG_EDX, 0x00000040U,                VENDOR_AMD, "100 MHz multiplier control"},
            { 0x80000007U, 0U, REG_EDX, 0x00000080U,                VENDOR_AMD, "Hardware P-state control"},
            { 0x80000007U, 0U, REG_EDX, 0x00000100U, VENDOR_INTEL | VENDOR_AMD, "Invariant TSC"},
            { 0x80000007U, 0U, REG_EDX, 0x00000200U,                VENDOR_AMD, "Core performance boost"},
            { 0x80000007U, 0U, REG_EDX, 0x00000400U,                VENDOR_AMD, "Read-only effective frequency interface"},
            { 0x80000007U, 0U, REG_EDX, 0x00000800U,                VENDOR_AMD, "Processor feedback interface"},
            { 0x80000007U, 0U, REG_EDX, 0x00001000U,                VENDOR_AMD, "Core power reporting"},
            { 0x80000007U, 0U, REG_EDX, 0x00002000U,                VENDOR_AMD, "Connected standby"},
            { 0x80000007U, 0U, REG_EDX, 0x00004000U,                VENDOR_AMD, "Running average power limit (RAPL)"},

        /*  Extended Feature Extensions ID (8000_0008h) */
            { 0x80000008U, 0U, REG_EBX, 0x00000001U,                VENDOR_AMD, "CLZERO instruction"},
            { 0x80000008U, 0U, REG_EBX, 0x00000002U,                VENDOR_AMD, "Instructions retired count support (IRPerf)"},
            { 0x80000008U, 0U, REG_EBX, 0x00000004U,                VENDOR_AMD, "XSAVE always saves/restores error pointers"},
            { 0x80000008U, 0U, REG_EBX, 0x00000008U,                VENDOR_AMD, "INVLPGB and TLBSYNC instruction"},
            { 0x80000008U, 0U, REG_EBX, 0x00000010U,                VENDOR_AMD, "RDPRU instruction"},
        /*  { 0x80000008U, 0U, REG_EBX, 0x00000020U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000008U, 0U, REG_EBX, 0x00000040U,                VENDOR_AMD, "Memory bandwidth enforcement (MBE)"},
        /*  { 0x80000008U, 0U, REG_EBX, 0x00000080U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000008U, 0U, REG_EBX, 0x00000100U,                VENDOR_AMD, "MCOMMIT instruction"},
            { 0x80000008U, 0U, REG_EBX, 0x00000200U, VENDOR_INTEL | VENDOR_AMD, "WBNOINVD (Write back and do not invalidate cache)"},
            { 0x80000008U, 0U, REG_EBX, 0x00000400U,                VENDOR_AMD, "LBR extensions"},
        /*  { 0x80000008U, 0U, REG_EBX, 0x00000800U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000008U, 0U, REG_EBX, 0x00001000U,                VENDOR_AMD, "Indirect Branch Prediction Barrier (IBPB)"},
            { 0x80000008U, 0U, REG_EBX, 0x00002000U,                VENDOR_AMD, "WBINVD (Write back and invalidate cache)"},
            { 0x80000008U, 0U, REG_EBX, 0x00004000U,                VENDOR_AMD, "Indirect Branch Restricted Speculation (IBRS)"},
            { 0x80000008U, 0U, REG_EBX, 0x00008000U,                VENDOR_AMD, "Single Thread Indirect Branch Predictor (STIBP)"},
        /*  { 0x80000008U, 0U, REG_EBX, 0x00010000U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000008U, 0U, REG_EBX, 0x00020000U,                VENDOR_AMD, "STIBP always on"},
            { 0x80000008U, 0U, REG_EBX, 0x00040000U,                VENDOR_AMD, "IBRS preferred over software solution"},
            { 0x80000008U, 0U, REG_EBX, 0x00080000U,                VENDOR_AMD, "IBRS provides Same Mode Protection"},
            { 0x80000008U, 0U, REG_EBX, 0x00100000U,                VENDOR_AMD, "EFER.LMLSE is unsupported"},
            { 0x80000008U, 0U, REG_EBX, 0x00200000U,                VENDOR_AMD, "INVLPGB for guest nested translations"},
        /*  { 0x80000008U, 0U, REG_EBX, 0x00400000U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x80000008U, 0U, REG_EBX, 0x00800000U,                VENDOR_AMD, "Protected Processor Inventory Number (PPIN)"},
            { 0x80000008U, 0U, REG_EBX, 0x01000000U,                VENDOR_AMD, "Speculative Store Bypass Disable (SSBD)"},
            { 0x80000008U, 0U, REG_EBX, 0x02000000U,                VENDOR_AMD, "VIRT_SPEC_CTL"},
            { 0x80000008U, 0U, REG_EBX, 0x04000000U,                VENDOR_AMD, "SSBD no longer needed"},
        /*  { 0x80000008U, 0U, REG_EBX, 0x08000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x80000008U, 0U, REG_EBX, 0x10000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x80000008U, 0U, REG_EBX, 0x20000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x80000008U, 0U, REG_EBX, 0x40000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x80000008U, 0U, REG_EBX, 0x80000000U,                VENDOR_AMD, ""}, */   /* Reserved */

        /*  SVM Revision and Feature Identification (8000_000Ah) */
            { 0x8000000AU, 0U, REG_EDX, 0x00000001U,                VENDOR_AMD, "Nested paging"},
            { 0x8000000AU, 0U, REG_EDX, 0x00000002U,                VENDOR_AMD, "LBR virtualization"},
            { 0x8000000AU, 0U, REG_EDX, 0x00000004U,                VENDOR_AMD, "SVM lock"},
            { 0x8000000AU, 0U, REG_EDX, 0x00000008U,                VENDOR_AMD, "NRIP save"},
            { 0x8000000AU, 0U, REG_EDX, 0x00000010U,                VENDOR_AMD, "MSR-based TSC rate control"},
            { 0x8000000AU, 0U, REG_EDX, 0x00000020U,                VENDOR_AMD, "VMCB clean bits"},
            { 0x8000000AU, 0U, REG_EDX, 0x00000040U,                VENDOR_AMD, "Flush by ASID"},
            { 0x8000000AU, 0U, REG_EDX, 0x00000080U,                VENDOR_AMD, "Decode assists"},
        /*  { 0x8000000AU, 0U, REG_EDX, 0x00000100U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x00000200U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x8000000AU, 0U, REG_EDX, 0x00000400U,                VENDOR_AMD, "Pause intercept filter"},
            { 0x8000000AU, 0U, REG_EDX, 0x00000800U,                VENDOR_AMD, "Encrypted µcode patch"},
            { 0x8000000AU, 0U, REG_EDX, 0x00001000U,                VENDOR_AMD, "PAUSE filter threshold"},
            { 0x8000000AU, 0U, REG_EDX, 0x00002000U,                VENDOR_AMD, "AMD virtual interrupt controller"},
        /*  { 0x8000000AU, 0U, REG_EDX, 0x00004000U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x8000000AU, 0U, REG_EDX, 0x00008000U,                VENDOR_AMD, "Virtualized VMLOAD/VMSAVE"},
            { 0x8000000AU, 0U, REG_EDX, 0x00010000U,                VENDOR_AMD, "Virtualized GIF"},
            { 0x8000000AU, 0U, REG_EDX, 0x00020000U,                VENDOR_AMD, "Guest mode execution trap (GMET)"},
        /*  { 0x8000000AU, 0U, REG_EDX, 0x00040000U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x8000000AU, 0U, REG_EDX, 0x00080000U,                VENDOR_AMD, "SVM supervisor shadow stack restrictions"},
            { 0x8000000AU, 0U, REG_EDX, 0x00100000U,                VENDOR_AMD, "SPEC_CTRL virtualization"},
        /*  { 0x8000000AU, 0U, REG_EDX, 0x00200000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x00400000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x00800000U,                VENDOR_AMD, ""}, */   /* Reserved */
            { 0x8000000AU, 0U, REG_EDX, 0x01000000U,                VENDOR_AMD, "INVLPGB/TLBSYNC hypervisor enable"},
        /*  { 0x8000000AU, 0U, REG_EDX, 0x02000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x04000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x08000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x10000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x20000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x40000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000000AU, 0U, REG_EDX, 0x80000000U,                VENDOR_AMD, ""}, */   /* Reserved */

        /*  Performance Optimization Identifiers (8000_001Ah) */
            { 0x8000001AU, 0U, REG_EAX, 0x00000001U,                VENDOR_AMD, "128-bit SSE full-width pipelines (FP128)"},
            { 0x8000001AU, 0U, REG_EAX, 0x00000002U,                VENDOR_AMD, "Efficient MOVU SSE instructions (MOVU)"},
            { 0x8000001AU, 0U, REG_EAX, 0x00000004U,                VENDOR_AMD, "256-bit AVX full-width pipelines (FP256)"},
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000008U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000010U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000020U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000040U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000080U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000100U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000200U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000400U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00000800U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00001000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00002000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00004000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00008000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00010000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00020000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00040000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00080000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00100000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00200000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00400000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x00800000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x01000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x02000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x04000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x08000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x10000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x20000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x40000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001AU, 0U, REG_EAX, 0x80000000U,                VENDOR_AMD, ""}, */   /* Reserved */

        /*  Instruction Based Sampling Identifiers (8000_001Bh) */
            { 0x8000001BU, 0U, REG_EAX, 0x00000001U,                VENDOR_AMD, "IBS feature flags valid (IBSFFV)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000002U,                VENDOR_AMD, "IBS fetch sampling (FetchSam)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000004U,                VENDOR_AMD, "IBS execution sampling (OpSam)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000008U,                VENDOR_AMD, "Read/write of op counter (RdWrOpCnt)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000010U,                VENDOR_AMD, "Op counting mode (OpCnt)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000020U,                VENDOR_AMD, "Branch target address reporting (BrnTrgt)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000040U,                VENDOR_AMD, "IBS op cur/max count extended by 7 bits (OpCntExt)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000080U,                VENDOR_AMD, "IBS RIP invalid indication (RipInvalidChk)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000100U,                VENDOR_AMD, "IBS fused branch micro-op indication (OpBrnFuse)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000200U,                VENDOR_AMD, "IBS fetch control extended MSR (IbsFetchCtlExtd)"},
            { 0x8000001BU, 0U, REG_EAX, 0x00000400U,                VENDOR_AMD, "IBS op data 4 MSR (IbsOpData4)"},
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00000800U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00001000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00002000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00004000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00008000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00010000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00020000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00040000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00080000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00100000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00200000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00400000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x00800000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x01000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x02000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x04000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x08000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x10000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x20000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x40000000U,                VENDOR_AMD, ""}, */   /* Reserved */
        /*  { 0x8000001BU, 0U, REG_EAX, 0x80000000U,                VENDOR_AMD, ""}, */   /* Reserved */

        /*  Centaur features (c000_0001h) */
            { 0xc0000001U, 0U, REG_EDX, 0x00000001U, VENDOR_CENTAUR           , "Alternate Instruction Set available"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000002U, VENDOR_CENTAUR           , "Alternate Instruction Set enabled"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000004U, VENDOR_CENTAUR           , "Random Number Generator available"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000008U, VENDOR_CENTAUR           , "Random Number Generator enabled"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000010U, VENDOR_CENTAUR           , "LongHaul MSR 0000_110Ah"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000020U, VENDOR_CENTAUR           , "FEMMS"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000040U, VENDOR_CENTAUR           , "Advanced Cryptography Engine (ACE) available"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000080U, VENDOR_CENTAUR           , "Advanced Cryptography Engine (ACE) enabled"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000100U, VENDOR_CENTAUR           , "Montgomery Multiplier and Hash Engine (ACE2) available"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000200U, VENDOR_CENTAUR           , "Montgomery Multiplier and Hash Engine (ACE2) enabled"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000400U, VENDOR_CENTAUR           , "Padlock hash engine (PHE) available"},
            { 0xc0000001U, 0U, REG_EDX, 0x00000800U, VENDOR_CENTAUR           , "Padlock hash engine (PHE) enabled"},
            { 0xc0000001U, 0U, REG_EDX, 0x00001000U, VENDOR_CENTAUR           , "Padlock montgomery multiplier (PMM) available"},
            { 0xc0000001U, 0U, REG_EDX, 0x00002000U, VENDOR_CENTAUR           , "Padlock montgomery multiplier (PMM) enabled"},

            // clang-format on
        }};

        /// <!-- description -->
        ///   @brief Get a CPUID function name from a function number
        ///
        /// <!-- inputs/outputs -->
        ///   @param fun the CPUID function number
        ///   @return the CPUID function name
        ///
        [[nodiscard]] static constexpr auto
        function_name(bsl::uint32 const &fun) noexcept -> bsl::cstr_type
        {
            /// <!-- description -->
            ///   @brief Declares function_name_t to associate a function number
            ///    with its name
            struct function_name_t final
            {
                /// @brief Declares a function number
                bsl::uint32 const fun;
                /// @brief Declares a function name
                bsl::cstr_type const name;
            };

            constexpr auto num_function_names{22_umx};
            constexpr bsl::array<function_name_t, num_function_names.get()> function_names{
                {{0x00000000U, "Largest Standard Function"},
                 {0x00000001U, "Standard Feature Information"},
                 {0x00000006U, "Thermal and Power Management Feature Flags"},
                 {0x00000007U, "Structured Extended Feature Flags"},
                 {0x00000014U, "Processor Trace Enumeration"},
                 {0x40000001U, "Hypervisor"},
                 {0x40000003U, "Hypervisor"},
                 {0x40000004U, "Hypervisor implementation recommendations"},
                 {0x40000006U, "Hypervisor hardware features enabled"},
                 {0x40000007U, "Hypervisor CPU management features"},
                 {0x40000008U, "Hypervisor shared virtual memory (SVM) features"},
                 {0x40000009U, "Nested hypervisor feature indentification"},
                 {0x4000000AU, "Nested hypervisor feature indentification"},
                 {0x80000000U, "Largest Extended Function"},
                 {0x80000001U, "Extended Feature Information"},
                 {0x80000007U, "RAS Capabilities"},
                 {0x80000007U, "Advanced Power Management information"},
                 {0x80000008U, "Extended Feature Extensions ID"},
                 {0x8000000AU, "SVM Revision and Feature Identification"},
                 {0x8000001AU, "Performance Optimization Identifiers"},
                 {0x8000001BU, "Instruction Based Sampling Identifiers"},
                 {0xc0000001U, "Centaur features"}}};

            for (auto const &fname : function_names) {
                if (fname.fun == fun) {
                    return fname.name;
                }
                bsl::touch();
            }

            return "";
        }

        /// <!-- description -->
        ///   @brief Print the CPUID feature
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T The type to query
        ///   @param output to output to use, e.g. bsl::debug()
        ///   @param entry the mv_cdl_entry_t entry
        ///   @param reg_name the reg name
        ///   @param bitnum the bit position number
        ///   @param name_color the color to print with, e.g. bsl::red
        ///   @param name the feature name or message to print
        ///   @param endl whether to append bsl::endl
        ///   @return Returns an instance of bsl::out<T>
        ///
        template<typename T>
        [[maybe_unused]] constexpr auto
        print_feature_out(
            bsl::out<T> const &output,
            hypercall::mv_cdl_entry_t const &entry,
            bsl::cstr_type const reg_name,
            bsl::safe_idx const &bitnum,
            bsl::string_view const &name_color,
            bsl::string_view const &name,
            bool const endl) const noexcept -> bsl::out<T>
        {
            auto const *mut_spacing{""};
            if (bitnum < 10_idx) {
                mut_spacing = " ";
            }
            else {
                bsl::touch();
            }

            output << "    ["              // --
                   << bsl::blu             // --
                   << entry.idx            // --
                   << bsl::rst             // --
                   << "]["                 // --
                   << bsl::blu             // --
                   << reg_name             // --
                   << bsl::rst             // --
                   << "]["                 // --
                   << mut_spacing          // --
                   << bsl::blu             // --
                   << bitnum               // --
                   << bsl::rst             // --
                   << "]: "                // --
                   << name_color           // --
                   << name << bsl::rst;    // --
            if (endl) {
                output << bsl::endl;    // --
            }
            else {
                bsl::touch();
            }
            return output;
        }

        /// <!-- description -->
        ///   @brief Print the CPUID feature
        ///
        /// <!-- inputs/outputs -->
        ///   @param entry the mv_cdl_entry_t entry
        ///   @param reg the register id in cpu_register_t
        ///   @param bitnum the bit position
        ///
        constexpr void
        print_feature(
            hypercall::mv_cdl_entry_t const &entry,
            cpu_register_t const reg,
            bsl::safe_idx const &bitnum) noexcept
        {
            bsl::uint32 mut_reg_val{};
            bsl::cstr_type mut_reg_name{};

            if (REG_EAX == reg) {
                mut_reg_val = entry.eax;
                mut_reg_name = "EAX";
            }
            else if (REG_EBX == reg) {
                mut_reg_val = entry.ebx;
                mut_reg_name = "EBX";
            }
            else if (REG_ECX == reg) {
                mut_reg_val = entry.ecx;
                mut_reg_name = "ECX";
            }
            else if (REG_EDX == reg) {
                mut_reg_val = entry.edx;
                mut_reg_name = "EDX";
            }

            auto const bitmask{1_u32 << bsl::to_u32_unsafe(bitnum.get())};
            bool const is_enabled_feature{(mut_reg_val & bitmask).is_pos()};
            if (!is_enabled_feature && !m_print_unsupported) {    // NOLINT
                return;
            }
            bsl::touch();

            cpu_feature_t const *mut_feature_found{nullptr};
            for (auto const &feature : features) {
                if (feature.fun != entry.fun) {
                    continue;
                }
                if (feature.idx != entry.idx) {
                    continue;
                }
                if (feature.bitmask != bitmask) {
                    continue;
                }
                if (feature.reg != reg) {
                    continue;
                }
                if ((feature.vendor & m_vendor).is_zero()) {
                    continue;
                }
                mut_feature_found = &feature;
                break;
            }

            if (!is_enabled_feature) {
                /// The feature is unsupported

                if (nullptr == mut_feature_found) {
                    return;
                }

                if (m_print_unsupported) {
                    print_feature_out(
                        bsl::debug(),
                        entry,
                        mut_reg_name,
                        bitnum,
                        bsl::rst,
                        mut_feature_found->name,
                        true);
                }
                else {
                    bsl::touch();
                }
            }
            else if (nullptr == mut_feature_found) {
                /// The feature doesn't exist or needs to be added to the feature list

                m_has_error = true;

                if (m_print_error) {
                    print_feature_out(
                        bsl::error(),
                        entry,
                        mut_reg_name,
                        bitnum,
                        bsl::bold_red,
                        "Not found in feature list",
                        true);
                }
                else {
                    bsl::touch();
                }
            }
            else {
                /// The feature is supported

                if (m_print_supported) {
                    print_feature_out(
                        bsl::debug(),
                        entry,
                        mut_reg_name,
                        bitnum,
                        bsl::bold_wht,
                        mut_feature_found->name,
                        true);
                }
                else {
                    bsl::touch();
                }
            }
        }

        /// <!-- description -->
        ///   @brief Prints the largest available function from eax
        ///
        /// <!-- inputs/outputs -->
        ///   @param fun the function number
        ///   @param eax the eax register data
        ///
        static constexpr void
        print_largest_fun_eax(bsl::uint32 const &fun, bsl::uint32 const &eax) noexcept
        {
            bsl::cstr_type mut_s{};
            if (fun == cpuid_fn0000_0000) {
                mut_s = "standard";
            }
            else if (fun == cpuid_fn8000_0000) {
                mut_s = "extended";
            }
            bsl::debug() << "    ["                // --
                         << bsl::blu               // --
                         << 0U                     // --
                         << bsl::rst               // --
                         << "]["                   // --
                         << bsl::blu               // --
                         << "EAX"                  // --
                         << bsl::rst               // --
                         << "][ " << bsl::blu      // --
                         << 0 << bsl::rst          // --
                         << "]: "                  // --
                         << bsl::bold_wht          // --
                         << "largest "             // --
                         << mut_s                  // --
                         << " function number "    // --
                         << bsl::hex(eax)          // --
                         << bsl::rst               // --
                         << bsl::endl;             // --
        }

        /// <!-- description -->
        ///   @brief Prints a function header
        ///
        /// <!-- inputs/outputs -->
        ///   @param fun the function number
        ///
        static constexpr void
        print_function(bsl::uint32 const &fun) noexcept
        {
            constexpr auto upper{16_u32};
            bsl::debug() << bsl::bold_wht                                              // --
                         << "Fn"                                                       // --
                         << bsl::fmt("04x", bsl::to_u16_unsafe(fun >> upper.get()))    // --
                         << "_"                                                        // --
                         << bsl::fmt("04x", bsl::to_u16_unsafe(fun))                   // --
                         << "h "                                                       // --
                         << function_name(fun)                                         // --
                         << bsl::rst                                                   // --
                         << bsl::endl;                                                 // --
        }

        /// <!-- description -->
        ///   @brief Print CPUID features
        ///
        /// <!-- inputs/outputs -->
        ///   @param cdl the mv_cdl_entry_t to print the leaf from
        ///
        constexpr void
        print_all_features(hypercall::mv_cdl_t const *const cdl) noexcept
        {
            bool const has_error{m_has_error};
            for (auto mut_i{bsl::safe_idx::magic_0()}; mut_i < bsl::to_idx(cdl->num_entries);
                 ++mut_i) {
                auto const *const entry{cdl->entries.at_if(mut_i)};
                if (bsl::safe_u32::magic_0().get() ==
                        static_cast<uint32_t>(entry->flags) &&         // NOLINT
                    bsl::safe_u32::magic_0().get() == entry->eax &&    // NOLINT
                    bsl::safe_u32::magic_0().get() == entry->ebx &&    // NOLINT
                    bsl::safe_u32::magic_0().get() == entry->ecx &&    // NOLINT
                    bsl::safe_u32::magic_0().get() == entry->edx) {
                    continue;
                }

                // NOLINTNEXTLINE(bsl-boolean-operators-forbidden)
                if (m_print_supported || m_print_unsupported || has_error) {
                    print_function(entry->fun);
                }
                else {
                    bsl::touch();
                }

                // NOLINTNEXTLINE(bsl-boolean-operators-forbidden)
                if ((cpuid_fn0000_0000.get() == entry->fun) ||
                    (cpuid_fn8000_0000.get() == entry->fun)) {

                    // NOLINTNEXTLINE(bsl-boolean-operators-forbidden)
                    if (m_print_supported || m_print_unsupported || has_error) {
                        print_largest_fun_eax(entry->fun, entry->eax);
                    }
                    else {
                        bsl::touch();
                    }
                    continue;
                }

                constexpr auto num_regs{4_umx};
                constexpr bsl::array<cpu_register_t, num_regs.get()> regs{{
                    REG_EAX,
                    REG_EBX,
                    REG_ECX,
                    REG_EDX,
                }};
                constexpr auto bitnum_max{32_idx};
                for (auto const &reg : regs) {
                    for (auto mut_bitnum{bsl::safe_idx::magic_0()}; mut_bitnum < bitnum_max;
                         ++mut_bitnum) {
                        print_feature(*entry, reg, mut_bitnum);
                    }
                }
            }
        }

    public:
        /// <!-- description -->
        ///   @brief Tells whether the printer succeeded. It succeeds when all
        ///    of the supported features, i.e. the enable bits in the output
        ///    registers have been found to have an associated feature for this
        ///    vendor.
        ///
        /// <!-- inputs/outputs -->
        ///    @return Returns true when no error occured.
        ///
        [[nodiscard]] constexpr auto
        succeeded() const noexcept -> bool
        {
            return !m_has_error;
        }

        /// <!-- description -->
        ///   @brief Print CPUID features
        ///
        /// <!-- inputs/outputs -->
        ///   @param cdl the mv_cdl_entry_t to print the leaf from
        ///    @param flags the print_on_unsupported and error_on_missing flags
        ///
        constexpr void
        print_features(hypercall::mv_cdl_t const *const cdl, bsl::safe_u64 const &flags) noexcept
        {
            m_print_supported = (flags & CPUID_PRINTER_FLAG_PRINT_SUPPORTED).is_pos();
            m_print_unsupported = (flags & CPUID_PRINTER_FLAG_PRINT_UNSUPPORTED).is_pos();
            m_print_error = (flags & CPUID_PRINTER_FLAG_PRINT_ERROR).is_pos();
            m_has_error = false;

            // TODO Detect vendor
            m_vendor = VENDOR_AMD;
            m_vendor_name = "AMD";

            // NOLINTNEXTLINE(bsl-boolean-operators-forbidden)
            if (m_print_error && (!m_print_supported) && (!m_print_unsupported)) {

                m_print_error = false;
                print_all_features(cdl);
                if (!m_has_error) {
                    return;
                }

                m_print_error = true;
            }
            else {
                bsl::touch();
            }

            print_all_features(cdl);
        }
    };
}
