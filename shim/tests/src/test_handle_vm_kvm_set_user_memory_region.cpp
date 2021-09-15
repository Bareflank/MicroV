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

#include "../../include/handle_vm_kvm_set_user_memory_region.h"

#include <helpers.hpp>
#include <kvm_userspace_memory_region.h>
#include <shim_vm_t.h>

#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace shim
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        init_tests();
        constexpr auto handle{&handle_vm_kvm_set_user_memory_region};

        bsl::ut_scenario{"success"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"success multiple pages"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x8000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"success multiple mdls #1"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x7D000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"success multiple mdls #2"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x80000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"hypervisor not detected"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    g_mut_hypervisor_detected = false;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_hypervisor_detected = true;
                    };
                };
            };
        };

        bsl::ut_scenario{"unaligned size"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{42_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"size out of bounds"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0xFFFFFFFFFFFFF000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"deleting a slot (size of 0) not implemented"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x0_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"unaligned gpa"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{42_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"gpa out of bounds"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0xFFFFFFFFFFFFF000_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"unaligned addr"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{42_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"NULL addr"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x0_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        /// TODO:
        /// - Check to make sure that the userspace address that was provided
        ///   is canonical. Otherwise MicroV will get mad.
        ///

        /// TODO:
        /// - Check to make sure that the provided flags are supported by MicroV
        ///   and then construct the MicroV flags as required.
        ///

        /// TODO:
        /// - Check to make sure that non of the slots overlap. This is not
        ///   allowed by the KVM API, and even if it were, MicroV would get
        ///   mad as it doesn't allow this either.
        ///

        bsl::ut_scenario{"slot out of bounds"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto slot{0xFFFF_u32};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.slot = slot.get();
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"modifying a slot is not implemented"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_SUCCESS == handle(&mut_args, &mut_vm));
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"KVM_CAP_MULTI_ADDRESS_SPACE not supported"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto slot{0x10000_u32};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.slot = slot.get();
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"g_mut_platform_mlock fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    g_mut_platform_mlock = SHIM_FAILURE;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                    bsl::ut_cleanup{} = [&]() noexcept {
                        g_mut_platform_mlock = SHIM_SUCCESS;
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_mmio_map fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x80000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    g_mut_mv_vm_op_mmio_map = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_mmio_map fails"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x1000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    g_mut_mv_vm_op_mmio_map = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_mmio_map fails multiple mdls #1"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x7D000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    g_mut_mv_vm_op_mmio_map = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        bsl::ut_scenario{"mv_vm_op_mmio_map fails multiple mdls #2"} = []() noexcept {
            bsl::ut_given{} = [&]() noexcept {
                kvm_userspace_memory_region mut_args{};
                shim_vm_t mut_vm{};
                constexpr auto gpa{0x0_umx};
                constexpr auto size{0x80000_umx};
                constexpr auto addr{0x1000_umx};
                bsl::ut_when{} = [&]() noexcept {
                    mut_args.guest_phys_addr = gpa.get();
                    mut_args.memory_size = size.get();
                    mut_args.userspace_addr = addr.get();
                    g_mut_mv_vm_op_mmio_map = bsl::safe_u64::magic_1().get();
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(SHIM_FAILURE == handle(&mut_args, &mut_vm));
                    };
                };
            };
        };

        return fini_tests();
    }
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();
    return shim::tests();
}
