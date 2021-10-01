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

#ifndef CR_ACCESS_T_HPP
#define CR_ACCESS_T_HPP

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief Defines the type of control register access
    ///
    enum class cr_access_t : bsl::uint8
    {
        /// @brief defines a read from CR0
        cr0_read = (0_u8).get(),
        /// @brief defines a write to CR0
        cr0_write = (1_u8).get(),
        /// @brief defines a read from CR2
        cr2_read = (2_u8).get(),
        /// @brief defines a write to CR2
        cr2_write = (3_u8).get(),
        /// @brief defines a read from CR3
        cr3_read = (4_u8).get(),
        /// @brief defines a write to CR3
        cr3_write = (5_u8).get(),
        /// @brief defines a read from CR4
        cr4_read = (6_u8).get(),
        /// @brief defines a write to CR4
        cr4_write = (7_u8).get(),
        /// @brief defines a read from CR8
        cr8_read = (8_u8).get(),
        /// @brief defines a write to CR8
        cr8_write = (9_u8).get(),
    };
}

#endif
