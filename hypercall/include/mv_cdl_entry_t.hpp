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

#ifndef MV_CDL_ENTRY_T_HPP
#define MV_CDL_ENTRY_T_HPP

#include <mv_cpuid_flag_t.hpp>    // IWYU pragma: no_include "mv_cpuid_flag_t.hpp"

#include <bsl/cstdint.hpp>

#pragma pack(push, 1)

namespace hypercall
{
    /// <!-- description -->
    ///   @brief See mv_cdl_t for more details
    ///
    struct mv_cdl_entry_t final
    {
        /// @brief stores the CPUID function input
        uint32_t fun;
        /// @brief stores the CPUID index input
        uint32_t idx;
        /// @brief stores an MicroV specific flags
        mv_cpuid_flag_t flags;
        /// @brief stores the CPUID eax output
        uint32_t eax;
        /// @brief stores the CPUID ebx output
        uint32_t ebx;
        /// @brief stores the CPUID ecx output
        uint32_t ecx;
        /// @brief stores the CPUID edx output
        uint32_t edx;
        /// @brief reserved
        uint32_t reserved;
    };
}

#pragma pack(pop)

#endif
