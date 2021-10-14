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
#include <ioctl.hpp>
#include <kvm_mp_state.hpp>
#include <shim_platform_interface.hpp>

#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

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
    lib::ioctl mut_system_ctl{shim::DEVICE_NAME};
    auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
    lib::ioctl mut_vm{bsl::to_i32(vmfd)};
    auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
    lib::ioctl mut_vcpu{bsl::to_i32(vcpufd)};

    constexpr auto mut_initial_state{1_u32};
    constexpr auto mut_running_state{0_u32};
    constexpr auto mut_wait_state{3_u32};
    constexpr auto mut_init_state{2_u32};
    constexpr auto mut_sipi_state{4_u32};
    shim::kvm_mp_state mut_mpstate{};
    bsl::safe_i64 mut_ret{};

    // Initial
    {
        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate.mp_state = mut_wait_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());
        mut_mpstate.mp_state = mut_sipi_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());
        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate.mp_state = mut_init_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate.mp_state = mut_sipi_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
    }
    // Running
    {
        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_init_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_sipi_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_wait_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
    }
    // Wait
    {
        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_wait_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_init_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_sipi_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_wait_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
    }
    // INIT
    {

        mut_mpstate.mp_state = mut_init_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_initial_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_running_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_wait_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_sipi_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
    }
    // SIPI
    {
        mut_mpstate.mp_state = mut_init_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_sipi_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_initial_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_init_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_wait_state.get();
        mut_ret = mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate);
        integration::verify(mut_ret != bsl::safe_i64::magic_0());

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
    }
    {
        constexpr auto num_loops{0x100_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            mut_mpstate.mp_state = mut_initial_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate.mp_state = mut_init_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate.mp_state = mut_sipi_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate.mp_state = mut_running_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate.mp_state = mut_wait_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        }
    }
    return bsl::exit_success;
}
