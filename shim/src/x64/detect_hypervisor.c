/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <intrinsic_cpuid.h>
#include <mv_types.h>

/**
 * <!-- description -->
 *   @brief Detects if the shim is running inside a guest VM
 *     allowing it to attempt to communicate.
 *
 * <!-- inputs/outputs -->
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
detect_hypervisor(void) NOEXCEPT
{
    uint32_t const fn0000_0001 = 0x00000001U;
    uint32_t const hypervisor_bit = 0x80000000U;

    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;

    /// TODO:
    /// - In release mode, this should be changed to cache the results
    ///   so that CPUID only called once per-PP. Otherwise, this would
    ///   result in a VMExit, and since this is called on every IOCTL,
    ///   that would be a massive amount of overhead.
    ///
    /// - This is called on every IOCTL in debug mode because you can
    ///   turn off the hypervisor without closing the shim. When this
    ///   happens, the vmcall instruction is no longer useable. So you
    ///   end up with a situation where the hypervisor was detected when
    ///   the shim was opened, but then later on, the hypervisor is no
    ///   longer there. The ability to turn off the hypervisor is a
    ///   developer-only feature. In release mode, we would run MicroV
    ///   from UEFI, and it would be on all the time and not be allowed
    ///   to turn off, so this is a non-issue, and therefore should
    ///   only be run once.
    ///

    eax = fn0000_0001;
    ecx = 0U;
    intrinsic_cpuid(&eax, &ebx, &ecx, &edx);

    if (ecx & hypervisor_bit) {
        return SHIM_SUCCESS;
    }

    return SHIM_FAILURE;
}
