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
#include <mv_run_t.hpp>

#include <bsl/array.hpp>
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

        auto const vm_image{integration::load_vm("vm_cross_compile/bin/32bit_io_test")};

        // Verify run works with port IO
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::map_vm(vm_image, {}, vmid);
            integration::initialize_register_state_for_16bit_vm(vsid);

            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);

            constexpr auto expected_addr{0x10_u64};
            constexpr auto expected_data{0x02_u8};
            constexpr auto expected_reps{0x01_u64};
            constexpr auto expected_type{0x01_u64};
            constexpr auto expected_size{mv_bit_size_t::mv_bit_size_t_16};

            auto *const pmut_run_return{to_0<mv_run_return_t>()};
            auto *const pmut_exit_io{&pmut_run_return->mv_exit_io};

            integration::verify(pmut_exit_io->addr == expected_addr);
            integration::verify(io_to<bsl::uint8>(pmut_exit_io->data) == expected_data);
            integration::verify(pmut_exit_io->reps == expected_reps);
            integration::verify(pmut_exit_io->type == expected_type);
            integration::verify(pmut_exit_io->size == expected_size);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vsid));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vpid));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid));
        }

        // Verify run works with port IO strings
        {
            auto const vmid{mut_hvc.mv_vm_op_create_vm()};
            auto const vpid{mut_hvc.mv_vp_op_create_vp(vmid)};
            auto const vsid{mut_hvc.mv_vs_op_create_vs(vpid)};

            integration::verify(vmid.is_valid_and_checked());
            integration::verify(vpid.is_valid_and_checked());
            integration::verify(vsid.is_valid_and_checked());

            integration::map_vm(vm_image, {}, vmid);
            integration::initialize_register_state_for_16bit_vm(vsid);

            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);

            constexpr auto expected_data_size{24_u64};
            constexpr bsl::array<bsl::uint8, expected_data_size.get()> expected_data{
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,    // --
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,    // --
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,    // --
            };
            constexpr auto expected_addr{0x10_u64};
            auto const expected_data_8{*reinterpret_cast<bsl::uint8 const*>(expected_data.at_if({}))};
            auto const expected_data_16{*reinterpret_cast<bsl::uint16 const*>(expected_data.at_if({}))};
            auto const expected_data_32{*reinterpret_cast<bsl::uint32 const*>(expected_data.at_if({}))};
            constexpr auto expected_reps{0x01_u64};
            constexpr auto expected_type{0x01_u64};
            constexpr auto expected_size_8{mv_bit_size_t::mv_bit_size_t_8};
            constexpr auto expected_size_16{mv_bit_size_t::mv_bit_size_t_16};
            constexpr auto expected_size_32{mv_bit_size_t::mv_bit_size_t_32};

            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);

            auto *const pmut_run_return{to_0<mv_run_return_t>()};
            auto *const pmut_exit_io{&pmut_run_return->mv_exit_io};

            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            integration::verify(pmut_exit_io->addr == expected_addr);
            integration::verify(io_to<bsl::uint8>(pmut_exit_io->data) == expected_data_8);
            integration::verify(pmut_exit_io->reps == expected_reps);
            integration::verify(pmut_exit_io->type == expected_type);
            integration::verify(pmut_exit_io->size == expected_size_8);

            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            integration::verify(pmut_exit_io->addr == expected_addr);
            integration::verify(io_to<bsl::uint16>(pmut_exit_io->data) == expected_data_16);
            integration::verify(pmut_exit_io->reps == expected_reps);
            integration::verify(pmut_exit_io->type == expected_type);
            integration::verify(pmut_exit_io->size == expected_size_16);

            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            integration::verify(pmut_exit_io->addr == expected_addr);
            integration::verify(io_to<bsl::uint32>(pmut_exit_io->data) == expected_data_32);
            integration::verify(pmut_exit_io->reps == expected_reps);
            integration::verify(pmut_exit_io->type == expected_type);
            integration::verify(pmut_exit_io->size == expected_size_32);

            // Verify REP prefix works
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            integration::verify(pmut_exit_io->addr == expected_addr);
            integration::verify(pmut_exit_io->reps == expected_data_size);
            integration::verify(pmut_exit_io->type == expected_type);
            integration::verify(pmut_exit_io->size == expected_size_8);
            for (auto mut_i{0_idx}; mut_i < expected_data.size(); ++mut_i) {
                integration::verify(*pmut_exit_io->data.at_if(mut_i) == *expected_data.at_if(mut_i));
            }

            // Prepare data for page boudary verification
            constexpr auto expected_string_data_size{MV_RUN_MAX_IOMEM_SIZE};
            bsl::array<bsl::uint8, expected_string_data_size.get()> expected_string_data{};
            bsl::builtin_memcpy(expected_string_data.data(), expected_data.data(), expected_data.size_bytes());
            auto mut_i{bsl::to_idx(expected_data.size_bytes())};
            for (auto mut_j{0_idx}; mut_i < expected_string_data_size; ++mut_i, ++mut_j) {
                *expected_string_data.at_if(mut_i) = bsl::to_u8_unsafe(mut_j.get()).get();
            }

            // Verify handling page boudary works
            mut_exit_reason = integration::run_until_non_interrupt_exit(vsid);
            integration::verify(mut_exit_reason == mv_exit_reason_t::mv_exit_reason_t_io);
            integration::verify(pmut_exit_io->addr == expected_addr);
            integration::verify(pmut_exit_io->reps == expected_string_data_size);
            integration::verify(pmut_exit_io->type == expected_type);
            integration::verify(pmut_exit_io->size == expected_size_8);

            for (mut_i = {} ; mut_i < expected_string_data_size; ++mut_i) {
                bsl::print() << " " << bsl::hex(*pmut_exit_io->data.at_if(mut_i));
            }
            bsl::print() << bsl::endl;

            for (mut_i = {}; mut_i < expected_data_size; ++mut_i) {
                integration::verify(*pmut_exit_io->data.at_if(mut_i) == *expected_data.at_if(mut_i));
            }
            for (; mut_i < expected_string_data_size; ++mut_i) {
                bsl::debug() << " mut_i " << bsl::hex(mut_i) << " " << bsl::hex(*pmut_exit_io->data.at_if(mut_i)) << " == " << bsl::hex(*expected_string_data.at_if(mut_i)) << bsl::endl;
                integration::verify(*pmut_exit_io->data.at_if(mut_i) == *expected_string_data.at_if(mut_i));
            }

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
