/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef KVM_CONSTANTS_HPP
#define KVM_CONSTANTS_HPP

#include <bsl/convert.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// @brief defines the size of the API version
    constexpr auto KVM_API_VERSION{12_i64};
    /// @brief defines the size of the KVM_CAP_USER_MEMORY
    constexpr auto KVM_CAP_USER_MEMORY{1_i64};
    /// @brief defines the size of the KVM_CAP_SET_TSS_ADDR
    constexpr auto KVM_CAP_SET_TSS_ADDR{1_i64};
    /// @brief defines the size of the KVM_CAP_EXT_CPUID
    constexpr auto KVM_CAP_EXT_CPUID{1_i64};
    /// @brief defines the size of the KVM_CAP_NR_VCPUS
    constexpr auto KVM_CAP_NR_VCPUS{1_i64};
    /// @brief defines the size of the KVM_CAP_NR_MEMSLOTS
    constexpr auto KVM_CAP_NR_MEMSLOTS{64_i64};
    /// @brief defines the size of the KVM_CAP_MP_STATE
    constexpr auto KVM_CAP_MP_STATE{1_i64};
    /// @brief defines the size of the KVM_CAP_DESTROY_MEMORY_REGION_WORKS
    constexpr auto KVM_CAP_DESTROY_MEMORY_REGION_WORKS{1_i64};
    /// @brief defines the size of the KVM_CAP_JOIN_MEMORY_REGIONS_WORKS
    constexpr auto KVM_CAP_JOIN_MEMORY_REGIONS_WORKS{1_i64};
    /// @brief defines the size of the KVM_CAP_MCE
    constexpr auto KVM_CAP_MCE{32_i64};
    /// @brief defines the size of the KVM_CAP_GET_TSC_KHZ
    constexpr auto KVM_CAP_GET_TSC_KHZ{1_i64};
    /// @brief defines the size of the KVM_CAP_MAX_VCPUS
    constexpr auto KVM_CAP_MAX_VCPUS{128_i64};
    /// @brief defines the size of the KVM_CAP_TSC_DEADLINE_TIMER
    constexpr auto KVM_CAP_TSC_DEADLINE_TIMER{1_i64};
    /// @brief defines the size of the KVM_CAP_MAX_VCPU_ID
    constexpr auto KVM_CAP_MAX_VCPU_ID{32767_i64};
    /// @brief defines the size of the KVM_CAP_UNSUPPORTED
    constexpr auto KVM_CAP_UNSUPPORTED{0_i64};
    /// @brief defines the size of the KVM_CAP_IMMEDIATE_EXIT
    constexpr auto KVM_CAP_IMMEDIATE_EXIT{1_i64};
    /// @brief defines the size of the KVM_MP_INITIAL_STATE
    constexpr auto KVM_MP_RUNNING_STATE{0_u32};
    /// @brief defines the size of the KVM_MP_RUNNING_STATE
    constexpr auto KVM_MP_UNINITIALIZED_STATE{1_u32};
    /// @brief defines the size of the KVM_MP_WAIT_STATE
    constexpr auto KVM_MP_INIT_RECEIVED_STATE{2_u32};
    /// @brief defines the size of the KVM_MP_INIT_STATE
    constexpr auto KVM_MP_HALTED_STATE{3_u32};
    /// @brief defines the size of the KVM_MP_SIPI_STATE
    constexpr auto KVM_MP_SIPI_STATE{4_u32};

}
#pragma pack(pop)

#endif
