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
#include <kvm_constants.hpp>
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
    constexpr auto mut_initial_state{1_u32};
    constexpr auto mut_running_state{0_u32};
    constexpr auto mut_wait_state{3_u32};
    constexpr auto mut_init_state{2_u32};
    constexpr auto mut_sipi_state{4_u32};

    bsl::enable_color();
    integration::ioctl_t mut_system_ctl{shim::DEVICE_NAME};
    auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
    integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

    auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};

    integration::ioctl_t mut_vcpu{bsl::to_i32(vcpufd)};
    shim::kvm_mp_state mut_mpstate{};

    //nullptr passed
    {
        bsl::safe_i32 mut_ret{};
        mut_ret = bsl::to_i32(
            integration::platform_ioctl(bsl::to_i32(vcpufd).get(), shim::KVM_GET_MP_STATE.get()));
        integration::verify(mut_ret.is_neg());
    }
    //Initial
    {
        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_UNINITIALIZED_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_UNINITIALIZED_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_init_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_INIT_RECEIVED_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_sipi_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_SIPI_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_UNINITIALIZED_STATE == mut_mpstate.mp_state);
    }
    //Running
    {
        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_wait_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_HALTED_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_UNINITIALIZED_STATE == mut_mpstate.mp_state);
    }
    // Wait
    {

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_wait_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_HALTED_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_wait_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_HALTED_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_UNINITIALIZED_STATE == mut_mpstate.mp_state);
    }
    // INIT
    {

        mut_mpstate.mp_state = mut_init_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_INIT_RECEIVED_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_sipi_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_SIPI_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_UNINITIALIZED_STATE == mut_mpstate.mp_state);
    }
    // SIPI
    {
        mut_mpstate.mp_state = mut_init_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_INIT_RECEIVED_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_sipi_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_SIPI_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_running_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

        mut_mpstate.mp_state = mut_initial_state.get();
        integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
        mut_mpstate = {};
        integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
        integration::verify(shim::KVM_MP_UNINITIALIZED_STATE == mut_mpstate.mp_state);
    }
    {
        constexpr auto num_loops{0x100_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            mut_mpstate.mp_state = mut_initial_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate = {};
            integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
            integration::verify(shim::KVM_MP_UNINITIALIZED_STATE == mut_mpstate.mp_state);

            mut_mpstate.mp_state = mut_init_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate = {};
            integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
            integration::verify(shim::KVM_MP_INIT_RECEIVED_STATE == mut_mpstate.mp_state);

            mut_mpstate.mp_state = mut_sipi_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate = {};
            integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
            integration::verify(shim::KVM_MP_SIPI_STATE == mut_mpstate.mp_state);

            mut_mpstate.mp_state = mut_running_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate = {};
            integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
            integration::verify(shim::KVM_MP_RUNNING_STATE == mut_mpstate.mp_state);

            mut_mpstate.mp_state = mut_wait_state.get();
            integration::verify(mut_vcpu.write(shim::KVM_SET_MP_STATE, &mut_mpstate).is_zero());
            mut_mpstate = {};
            integration::verify(mut_vcpu.read(shim::KVM_GET_MP_STATE, &mut_mpstate).is_zero());
            integration::verify(shim::KVM_MP_HALTED_STATE == mut_mpstate.mp_state);
        }
    }
    return bsl::exit_success;
}
