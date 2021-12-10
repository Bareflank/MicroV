//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma GCC diagnostic ignored "-Wunused-result"
#include <cstdio>
#include <ctime>
#include <iostream>
#include <sys/mount.h>
#include <unistd.h>

/**
 * <!-- description -->
 *   @brief main function
 *
 * <!-- inputs/outputs -->
 *   @return //none
 */
[[nodiscard]] auto
main() noexcept -> int32_t
{
    mount("proc", "/proc", "proc", __u_long(0), "");
    freopen("/dev/ttyprintk", "w", stdout);    //NOLINT
    freopen("/dev/ttyprintk", "w", stderr);    //NOLINT

    while (true) {
        auto rawtime = time(nullptr);           //NOLINT
        auto *loctime = localtime(&rawtime);    //NOLINT

        std::cout << "hello from init: " << asctime(loctime);
        sleep(uint32_t(1));
    }
}
