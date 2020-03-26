/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef TSC_H
#define TSC_H

#ifndef BF_INTEL_X64
#error "unimplemented"
#endif

#include <arch/intel_x64/cpuid.h>

static uint64_t
calibrate_tsc_freq_khz()
{
    using namespace ::intel_x64::cpuid;
	auto [eax, ebx, ecx, edx] = ::x64::cpuid::get(0x15, 0, 0, 0);

    // Notes:
    //
    // For now we only support systems that provide the TSC frequency
    // through CPUID leaf 0x15. Please see the following:
    // - https://lore.kernel.org/patchwork/patch/689875/
    //
    // We could also get the information from the Plafrom Info MSR, but from
    // testing, this value doesn't seem to be as accurate as CPUID leaf 0x15.
    //
    // One issue is that for some CPUs, the frequency is reported as 0
    // even though the numerator and denominator are provided. The manual
    // states that this means the core crystal clock is not enumerated.
    // The Linux kernel maintains a whitelist to deal with this to ensure the
    // TSC frequency is accurate. This can be seen by the following links:
    // - https://lore.kernel.org/patchwork/patch/715512/
    // - https://elixir.bootlin.com/linux/v4.19.32/source/arch/x86/kernel/tsc.c#L610
    //
    // Where the Linux Kernel got this information is still a mystery as I
    // was not able to track down where the original 24MHz and 25MHz numbers
    // came from as it appears that it originated from this patch, which was
    // written by an Intel engineer, and already contained these values:
    // - https://lore.kernel.org/patchwork/patch/696814/
    //

    if (ecx == 0) {
        switch(feature_information::eax::get() & 0x000F00F0) {
            case 0x400E0:
            case 0x500E0:
            case 0x800E0:
            case 0x900E0:
                ecx = 24000;
                break;

            case 0x50050:
                ecx = 25000;
                break;

            case 0x500C0:
                ecx = 19200;
                break;

            default:
                break;
        };
    }
    else {
        ecx /= 1000;
    }

	if (eax == 0 || ebx == 0 || ecx == 0) {
        // We fail silently here giving an opportunity for bfexec to report
        // the error to the user without the need to debug over serial.
        return 0;
    }

    return (ecx * ebx) / eax;
}

#endif
