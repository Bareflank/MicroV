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

#ifndef INTEGRATION_UTILS_HPP
#define INTEGRATION_UTILS_HPP

#include <cstdlib>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace integration
{
    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    constexpr void
    verify(bool const test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    constexpr void
    verify(bsl::errc_type const test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of bsl::safe_integral to test.
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test where a
    ///     check failed.
    ///
    template<typename T>
    constexpr void
    verify(
        bsl::safe_integral<T> const &test, bsl::source_location const &sloc = bsl::here()) noexcept
    {
        if (bsl::unlikely(!test)) {
            bsl::print() << bsl::red << "integration test failed";
            bsl::print() << bsl::rst << sloc;
            exit(1);
        }
        else {
            bsl::touch();
        }
    }
}

#endif
