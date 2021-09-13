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
#include <mv_hypercall_t.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        mv_hypercall_t mut_hvc{};
        integration::verify(mut_hvc.initialize());

        // Destroy in order of creation
        {
            auto const vmid1{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid2{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid3{mut_hvc.mv_vm_op_create_vm()};

            integration::verify(vmid1.is_valid_and_checked());
            integration::verify(vmid2.is_valid_and_checked());
            integration::verify(vmid3.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid1));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid2));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid3));
        }

        // Destroy in reverse order
        {
            auto const vmid1{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid2{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid3{mut_hvc.mv_vm_op_create_vm()};

            integration::verify(vmid1.is_valid_and_checked());
            integration::verify(vmid2.is_valid_and_checked());
            integration::verify(vmid3.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid3));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid2));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid1));
        }

        // Destroy in random order
        {
            auto const vmid1{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid2{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid3{mut_hvc.mv_vm_op_create_vm()};

            integration::verify(vmid1.is_valid_and_checked());
            integration::verify(vmid2.is_valid_and_checked());
            integration::verify(vmid3.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid2));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid3));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid1));
        }

        // Create VMs until we run out. Then destroy them all.
        {
            bsl::array<bsl::safe_u16, bsl::to_umx(HYPERVISOR_MAX_VMS).get()> mut_vmids{};
            for (auto &mut_vmid : mut_vmids) {
                mut_vmid = mut_hvc.mv_vm_op_create_vm();
            }

            for (auto const &vmid : mut_vmids) {
                if (vmid.is_invalid()) {
                    continue;
                }

                integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
            }
        }

        // Make sure we can still create VMs
        {
            auto const vmid1{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid2{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid3{mut_hvc.mv_vm_op_create_vm()};

            integration::verify(vmid1.is_valid_and_checked());
            integration::verify(vmid2.is_valid_and_checked());
            integration::verify(vmid3.is_valid_and_checked());

            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid3));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid2));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid1));
        }

        return bsl::exit_success;
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
    return hypercall::tests();
}
