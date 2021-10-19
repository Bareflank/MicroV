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
#include <mv_exit_io_t.hpp>
#include <mv_exit_reason_t.hpp>
#include <mv_hypercall_t.hpp>
#include <mv_reg_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
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
        mv_exit_reason_t mut_exit_reason{};

        integration::initialize_globals();
        integration::initialize_shared_pages();

        auto const vm_image{integration::load_vm("vm_cross_compile/bin/16bit_io_in_out_test")};

        {
            constexpr auto initial_port10_val{0x42_u16};
            auto mut_port10{initial_port10_val};
            auto *const pmut_exit_io{to_0<mv_exit_io_t>()};

            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::map_vm(vm_image, {}, vmid);
            integration::initialize_register_state_for_16bit_vm(vsid);

            /// NOTE:
            /// - Let the guest run until we get our first exit. This should
            ///   be an IO instruction. It might be an interrupt too, and
            ///   if that becomes an issue, these integration tests will
            ///   need to be updated to account for that. Maybe another
            ///   helper that looks for a specific exit, or reruns if it
            ///   sees an intr or nmi.
            ///

            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            integration::verify(pmut_exit_io->type == MV_EXIT_IO_IN);

            /// NOTE:
            /// - The guest ran IN. Which means that it wants to read from the
            ///   emulated port. This port does not exist, in real life, so
            ///   we need to get it from somewhere. In this case, we will
            ///   simply store the value in our fake "port10". But this
            ///   could be attempting to read from an emulated configuration
            ///   space for PCI, or something else. Just depends on the port.
            ///
            /// - The guest VM is expecting to get it's value in AX. But this
            ///   is not always the case. All possible forms of IN/OUT should
            ///   be tested here. But to keep it simple, for now, we know that
            ///   the test wants AX, so we store the value in AX.
            ///
            /// - To give the guest it's value in AX, we need to set the
            ///   guest's AX with the value of our fake port. We only have
            ///   a way to set RAX, not AX. So we need to first, read the
            ///   value of RAX, change the AX portion, and then write it
            ///   back. This makes sure that only AX is changed, and that
            ///   the upper bits of RAX are left unchanged. Thankfully, we
            ///   set data to the value of RAX for both IN and OUT. So we
            ///   can just read the value of RAX from the data field.
            ///

            constexpr auto ax_mask{0xFFFFFFFFFFFF0000_u64};
            bsl::safe_u64 mut_rax{pmut_exit_io->data};
            mut_rax &= ax_mask;
            mut_rax |= bsl::to_u64(mut_port10);

            /// NOTE:
            /// - No need to use checked() or .is_poisoned() here because
            ///   binary arithmetic will never overflow, so the safe
            ///   integral will not trigger a requirement to check the
            ///   math above. It's only needed when you do +, -, *, / and %
            ///   for the most part. I have a really good set of notes in
            ///   the code found here:
            ///   https://github.com/Bareflank/bsl/blob/master/include/bsl/safe_integral.hpp#L75
            ///
            /// - Ok, now we have the value of RAX that the guest should
            ///   have. The next step is to give this to the guest. For
            ///   now, I will just write it using mv_vs_op_reg_set. But,
            ///   what really should happen is:
            ///   - implement mv_run_t. it is defined in the spec
            ///   - use to_0<mv_run_t>() to get a pointer to the shared page
            ///   - set reg0 to the value of rax
            ///   - implement support for mv_run_t on run so that registers
            ///     can be set when we run instead of needing two hypercalls
            ///

            integration::verify(mut_hvc.mv_vs_op_reg_set(vsid, mv_reg_t::mv_reg_t_rax, mut_rax));

            /// NOTE:
            /// - Now, all we need to do is run the guest again and wait for
            ///   the next IO which should be an out.
            ///

            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            integration::verify(pmut_exit_io->type == MV_EXIT_IO_OUT);

            /// NOTE:
            /// - Lets print the value of RAX to show that the guest read
            ///   our fake port, incremented the value, and wrote the new
            ///   value back to our fake port. We should see 0x43.
            ///

            bsl::print() << "IO port: "                                             // --
                         << bsl::cyn << bsl::hex(pmut_exit_io->addr) << bsl::rst    // --
                         << ", data: "                                              // --
                         << bsl::blu << bsl::hex(pmut_exit_io->data) << bsl::rst    // --
                         << bsl::endl;                                              // --

            /// NOTE:
            /// - Normally, the next step would be to store this new value
            ///   in our fake port so that the next time that the guest
            ///   wants to read it, the value is sitting there, but for now
            ///   this should be enough.
            ///
            /// - Whats next? Well:
            ///   - This needs to be implemented and tested on Intel.
            ///   - All of the port combinations should be tested. This
            ///     includes teh rep prefix versions. For string instructions
            ///     and other strange versions that we never see, you still
            ///     need an integration test, but what the integration test
            ///     should do is prove that the guest get's an unknown
            ///     failure when these instructions are used so that we can
            ///     prove that we will be told when this happens, just in
            ///     case we need to implement it later.
            ///   - All other combinations should be tested like register
            ///     size, data size, different ports, etc...
            ///   - Implement the mv_run_t stuff. This is really important
            ///     because port IO is already slow. Cutting the total number
            ///     of hypercalls in half will make a huge difference in
            ///     performance, and it is easy to implement. On a run exit,
            ///     check the shared page to see if any of the registers and
            ///     or msrs are dirty. If they are, write their results
            ///     before executing run. I would likely update the spec to
            ///     so that if reg0 is empty (i.e., unsupported), that you
            ///     do not need to check reg1, and so on, so that you don't
            ///     have to check all of them... you just check from 0 to
            ///     whenever unsupported is seen. Same for the MSRs, but
            ///     just use MSR 0 and "unsupported" since it doesn't exist.
            ///

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
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
