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

#include <integration_utils.hpp>
#include <ioctl_t.hpp>
#include <kvm_run.hpp>
#include <shim_platform_interface.hpp>
#include <signal.h>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_integral.hpp>
namespace
{
    /// @brief store the kvm_run struct
    shim::kvm_run *g_pmut_mut_run{};

    /// <!-- description -->
    ///   @brief Stops the execution of the guest VM
    ///
    /// <!-- inputs/outputs -->
    ///   @param sig the signal
    ///
    extern "C" void
    sig_handler(bsl::int32 const sig) noexcept
    {
        bsl::discard(sig);
        g_pmut_mut_run->immediate_exit = bsl::safe_u8::magic_1().get();
    }
}

/// <!-- description -->
///   @brief Provides the main entry point for this application.
///
/// <!-- inputs/outputs -->
///   @return bsl::exit_success on success, bsl::exit_failure otherwise.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();
    signal(SIGINT, &sig_handler);

    integration::ioctl_t mut_system{shim::DEVICE_NAME};
    integration::ioctl_t mut_vm{bsl::to_i32(mut_system.send(shim::KVM_CREATE_VM))};
    integration::ioctl_t mut_vcpu{bsl::to_i32(mut_vm.send(shim::KVM_CREATE_VCPU))};

    integration::initialize_16bit_vm(mut_vm, "vm_cross_compile/bin/16bit_endless_loop_test");
    g_pmut_mut_run = integration::initialize_16bit_vcpu(mut_vcpu);

    auto const ret{mut_vcpu.send(shim::KVM_RUN)};
    integration::verify(ret.is_neg());

    mut_vcpu.close();
    mut_vm.close();

    return bsl::exit_success;
}
