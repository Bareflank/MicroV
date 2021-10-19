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
#include <mv_bit_size_t.hpp>
#include <mv_exit_io_t.hpp>
#include <mv_exit_reason_t.hpp>
#include <mv_hypercall_t.hpp>

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
        // mv_exit_reason_t mut_exit_reason{};

        integration::initialize_globals();
        integration::initialize_shared_pages();

        auto const vm_image{integration::load_vm("vm_cross_compile/bin/32bit_endless_loop_test")};

        // Verify run works
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::map_vm(vm_image, {}, vmid);
            integration::initialize_register_state_for_16bit_vm(vsid);

            constexpr auto i_100{100_i64};
            constexpr auto i_20{20_i64};
            auto mut_i{i_100};
            while (bsl::safe_i64::magic_0() != (mut_i = (--mut_i).checked())) {
                if (mut_i == i_20) {
                    bsl::debug() << "injecting interrupt" << bsl::endl;
                    auto const vector{0_u64};
                    integration::verify(mut_hvc.mv_vs_op_queue_interrupt(vsid, vector));
                }
                else {
                    bsl::touch();
                }

                auto const exit_reason{mut_hvc.mv_vs_op_run(vsid)};
                switch (exit_reason) {
                    case hypercall::mv_exit_reason_t::mv_exit_reason_t_interrupt: {
                        bsl::debug() << "mv_exit_reason_t_interrupt" << bsl::endl;
                        continue;
                    }

                    case hypercall::mv_exit_reason_t::mv_exit_reason_t_nmi: {
                        bsl::debug() << "mv_exit_reason_t_nmi" << bsl::endl;
                        continue;
                    }

                    case mv_exit_reason_t::mv_exit_reason_t_io: {
                        auto *const pmut_exit_io{to_0<mv_exit_io_t>()};
                        bsl::debug()
                            << "mv_exit_reason_t_io "                                   // --
                            << "addr "                                                  // --
                            << bsl::hex(pmut_exit_io->addr)                             // --
                            << " data "                                                 // --
                            << bsl::hex(pmut_exit_io->data)                             // --
                            << " reps "                                                 // --
                            << bsl::hex(pmut_exit_io->reps)                             // --
                            << " type "                                                 // --
                            << bsl::hex(pmut_exit_io->type)                             // --
                            << " size "                                                 // --
                            << bsl::hex(static_cast<bsl::uint8>(pmut_exit_io->size))    // --
                            << bsl::endl;                                               // --

                        continue;
                    }

                    default: {
                        bsl::debug() << "exit_reason "                   // --
                                     << bsl::hex(to_u64(exit_reason))    // --
                                     << bsl::endl;                       // --
                        break;
                    }
                }
                exit(1);
            }
#if 0
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);

            constexpr auto expected_addr{0x10_u64};
            constexpr auto expected_data{0x02_u64};
            constexpr auto expected_reps{0x00_u64};
            constexpr auto expected_type{0x01_u64};
            constexpr auto expected_size{mv_bit_size_t::mv_bit_size_t_16};

            auto *const pmut_exit_io{to_0<mv_exit_io_t>()};
            integration::verify(pmut_exit_io->addr == expected_addr);
            integration::verify(pmut_exit_io->data == expected_data);
            integration::verify(pmut_exit_io->reps == expected_reps);
            integration::verify(pmut_exit_io->type == expected_type);
            integration::verify(pmut_exit_io->size == expected_size);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
#endif
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
