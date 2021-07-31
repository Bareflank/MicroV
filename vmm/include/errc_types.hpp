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

#ifndef ERRC_TYPES_HPP
#define ERRC_TYPES_HPP

#include <bsl/convert.hpp>
#include <bsl/errc_type.hpp>

namespace microv
{
    /// @brief Defines success and run current VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_success_run{10001};
    /// @brief Defines success and run parent VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_success_run_parent{10002};
    /// @brief Defines success, advance IP, and run current VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_success_advance_ip_and_run{10003};
    /// @brief Defines success, advance IP, and run parent VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_success_advance_ip_and_run_parent{10004};
    /// @brief Defines success and promote current VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_success_promote{10005};

    /// @brief Defines failure and run current VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_failure_run{-10001};
    /// @brief Defines failure and run parent VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_failure_run_parent{-10002};
    /// @brief Defines failure, advance IP, and run current VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_failure_advance_ip_and_run{-10003};
    /// @brief Defines failure, advance IP, and run parent VM, VP and VS
    // NOLINTNEXTLINE(bsl-name-case)
    constexpr bsl::errc_type vmexit_failure_advance_ip_and_run_parent{-10004};
}

#endif
