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
#include <kvm_dtable.hpp>
#include <kvm_segment.hpp>
#include <kvm_sregs.hpp>
#include <shim_platform_interface.hpp>

#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace
{
    /// @brief defines the segment base we expect
    constexpr auto EXPECTED_BASE{0x1234567890ABCDEF_u64};
    /// @brief defines the segment limit we expect
    constexpr auto EXPECTED_LIMIT{0x12345678_u32};
    /// @brief defines the segment selector we expect
    constexpr auto EXPECTED_SELECTOR{0x1234_u16};
    /// @brief defines the segment attrib type we expect
    constexpr auto EXPECTED_TYPE{0xF_u8};
    /// @brief defines the segment attrib present we expect
    constexpr auto EXPECTED_PRESENT{0x01_u8};
    /// @brief defines the segment attrib dpl we expect
    constexpr auto EXPECTED_DPL{0x03_u8};
    /// @brief defines the segment attrib db we expect
    constexpr auto EXPECTED_DB{0x01_u8};
    /// @brief defines the segment attrib l we expect
    constexpr auto EXPECTED_L{0x01_u8};
    /// @brief defines the segment attrib g we expect
    constexpr auto EXPECTED_G{0x01_u8};
    /// @brief defines the segment attrib avl we expect
    constexpr auto EXPECTED_AVL{0x01_u8};
    /// @brief defines the segment attrib s we expect
    constexpr auto EXPECTED_S{0x01_u8};
    /// @brief defines the segment attrib unusable we expect
    constexpr auto EXPECTED_UNUSABLE{0x01_u8};
    /// @brief defines the segment attrib padding we expect
    constexpr auto EXPECTED_PADDING{0x00_u8};

    /// @brief defines the descriptor table base we expect
    constexpr auto EXPECTED_DTABLE_BASE{0x1234567890ABCDEF_u64};
    /// @brief defines the descriptor table limit we expect
    constexpr auto EXPECTED_DTABLE_LIMIT{0x1234_u16};
    /// @brief defines the descriptor table padding we expect
    constexpr auto EXPECTED_DTABLE_PADDING{0x00_u16};

    /// @brief defines the segment base we expect
    constexpr auto EXPECTED_OTHER{0x1234567890ABCDEF_u64};

    /// @brief defines the expected segment information
    constexpr shim::kvm_segment G_SEGMENT{
        EXPECTED_BASE.get(),
        EXPECTED_LIMIT.get(),
        EXPECTED_SELECTOR.get(),
        EXPECTED_TYPE.get(),
        EXPECTED_PRESENT.get(),
        EXPECTED_DPL.get(),
        EXPECTED_DB.get(),
        EXPECTED_L.get(),
        EXPECTED_G.get(),
        EXPECTED_AVL.get(),
        EXPECTED_S.get(),
        EXPECTED_UNUSABLE.get(),
        EXPECTED_PADDING.get(),
    };

    /// @brief defines the expected descriptor table information
    constexpr shim::kvm_dtable G_DTABLE{
        EXPECTED_DTABLE_BASE.get(),
        EXPECTED_DTABLE_LIMIT.get(),
        EXPECTED_DTABLE_PADDING.get(),
        EXPECTED_DTABLE_PADDING.get(),
        EXPECTED_DTABLE_PADDING.get(),
    };

    /// @brief defines the expected sregs information
    constexpr shim::kvm_sregs G_SREGS{
        G_SEGMENT,
        G_SEGMENT,
        G_SEGMENT,
        G_SEGMENT,
        G_SEGMENT,
        G_SEGMENT,
        G_SEGMENT,
        G_SEGMENT,
        G_DTABLE,
        G_DTABLE,
        EXPECTED_OTHER.get(),
        EXPECTED_OTHER.get(),
        EXPECTED_OTHER.get(),
        EXPECTED_OTHER.get(),
        EXPECTED_OTHER.get(),
        EXPECTED_OTHER.get(),
        EXPECTED_OTHER.get(),
        {}};
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
    shim::kvm_sregs mut_sregs{G_SREGS};

    bsl::enable_color();
    integration::ioctl_t mut_system_ctl{shim::DEVICE_NAME};

    /// Verify that get/set works
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        integration::ioctl_t mut_vcpu{bsl::to_i32(vcpufd)};

        integration::verify(mut_vcpu.write(shim::KVM_SET_SREGS, &mut_sregs).is_zero());
        mut_sregs = {};
        integration::verify(mut_vcpu.write(shim::KVM_GET_SREGS, &mut_sregs).is_zero());

        integration::verify(EXPECTED_BASE == mut_sregs.cs.base);
        integration::verify(EXPECTED_LIMIT == mut_sregs.cs.limit);
        integration::verify(EXPECTED_SELECTOR == mut_sregs.cs.selector);
        integration::verify(EXPECTED_BASE == mut_sregs.ds.base);
        integration::verify(EXPECTED_LIMIT == mut_sregs.ds.limit);
        integration::verify(EXPECTED_SELECTOR == mut_sregs.ds.selector);
        integration::verify(EXPECTED_BASE == mut_sregs.es.base);
        integration::verify(EXPECTED_LIMIT == mut_sregs.es.limit);
        integration::verify(EXPECTED_SELECTOR == mut_sregs.es.selector);
        integration::verify(EXPECTED_BASE == mut_sregs.fs.base);
        integration::verify(EXPECTED_LIMIT == mut_sregs.fs.limit);
        integration::verify(EXPECTED_SELECTOR == mut_sregs.fs.selector);
        integration::verify(EXPECTED_BASE == mut_sregs.gs.base);
        integration::verify(EXPECTED_LIMIT == mut_sregs.gs.limit);
        integration::verify(EXPECTED_SELECTOR == mut_sregs.gs.selector);
        integration::verify(EXPECTED_BASE == mut_sregs.ss.base);
        integration::verify(EXPECTED_LIMIT == mut_sregs.ss.limit);
        integration::verify(EXPECTED_SELECTOR == mut_sregs.ss.selector);
        integration::verify(EXPECTED_BASE == mut_sregs.tr.base);
        integration::verify(EXPECTED_LIMIT == mut_sregs.tr.limit);
        integration::verify(EXPECTED_SELECTOR == mut_sregs.tr.selector);
        integration::verify(EXPECTED_BASE == mut_sregs.ldt.base);
        integration::verify(EXPECTED_LIMIT == mut_sregs.ldt.limit);
        integration::verify(EXPECTED_SELECTOR == mut_sregs.ldt.selector);
        integration::verify(EXPECTED_DTABLE_BASE == mut_sregs.gdt.base);
        integration::verify(EXPECTED_DTABLE_LIMIT == mut_sregs.gdt.limit);
        integration::verify(EXPECTED_DTABLE_BASE == mut_sregs.idt.base);
        integration::verify(EXPECTED_DTABLE_LIMIT == mut_sregs.idt.limit);
        integration::verify(bsl::safe_u64::magic_0() != mut_sregs.cr0);
        integration::verify(EXPECTED_OTHER == mut_sregs.cr2);
        integration::verify(EXPECTED_OTHER == mut_sregs.cr3);
        integration::verify(bsl::safe_u64::magic_0() != mut_sregs.cr4);
        integration::verify(EXPECTED_OTHER == mut_sregs.cr8);
        // integration::verify(EXPECTED_OTHER == mut_sregs.efer);
        // integration::verify(EXPECTED_OTHER == mut_sregs.apic_base);
    }

    // Try a bunch of times
    {
        auto const vmfd{mut_system_ctl.send(shim::KVM_CREATE_VM)};
        integration::ioctl_t mut_vm{bsl::to_i32(vmfd)};

        auto const vcpufd{mut_vm.send(shim::KVM_CREATE_VCPU)};
        integration::ioctl_t mut_vcpu{bsl::to_i32(vcpufd)};

        constexpr auto num_loops{0x1000_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            integration::verify(mut_vcpu.write(shim::KVM_SET_SREGS, &mut_sregs).is_zero());
        }
    }

    return bsl::exit_success;
}
