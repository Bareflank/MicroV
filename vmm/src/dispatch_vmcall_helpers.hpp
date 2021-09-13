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

#ifndef DISPATCH_VMCALL_HELPERS_HPP
#define DISPATCH_VMCALL_HELPERS_HPP

#include <bf_syscall_t.hpp>
#include <dispatch_vmcall_abi_helpers.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// ------------------------------------------------------------------------
    /// Validation Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Returns true if the provided version is supported.
    ///     Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register containing the version to verify
    ///   @return Returns true if the provided version is supported.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    is_version_supported(bsl::safe_u64 const &reg) noexcept -> bool
    {
        auto const version{bsl::to_u32(reg)};
        if (bsl::unlikely(version != hypercall::MV_SPEC_ID1_VAL)) {
            bsl::error() << "unsupported hypercall ABI "    // --
                         << bsl::hex(version)               // --
                         << bsl::endl                       // --
                         << bsl::here();                    // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the handle provided in tls.reg0 is valid.
    ///     Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @return Returns true if the handle provided in tls.reg0 is valid.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    verify_handle(syscall::bf_syscall_t const &sys) noexcept -> bool
    {
        if (bsl::unlikely(get_reg0(sys) != hypercall::MV_HANDLE_VAL)) {
            bsl::error() << "invalid handle "          // --
                         << bsl::hex(get_reg0(sys))    // --
                         << bsl::endl                  // --
                         << bsl::here();               // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the active VM is the root VM.
    ///     Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @return Returns true if the active VM is the root VM.
    ///     Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    verify_root_vm(syscall::bf_syscall_t const &sys) noexcept -> bool
    {
        if (bsl::unlikely(!sys.is_the_active_vm_the_root_vm())) {
            bsl::error() << "hypercall "                           // --
                         << bsl::hex(get_reg_hypercall(sys))       // --
                         << " is only supported by the root vm"    // --
                         << bsl::endl                              // --
                         << bsl::here();                           // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vm_t associated with the
    ///     provided vmid is destroyable. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param sys the bf_syscall_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vmid the ID of the VM to query
    ///   @return Returns true if the vm_t associated with the
    ///     provided vmid is destroyable. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vm_destroyable(
        tls_t const &tls,
        syscall::bf_syscall_t const &sys,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        bsl::safe_u16 const &vmid) noexcept -> bool
    {
        auto const active{vm_pool.is_active(tls, vmid)};
        if (bsl::unlikely(active.is_valid())) {
            bsl::error() << "vm "                         // --
                         << bsl::hex(vmid)                // --
                         << " is active on pp "           // --
                         << bsl::hex(active)              // --
                         << " and cannot be destroyed"    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return false;
        }

        if (bsl::unlikely(sys.is_vm_the_root_vm(vmid))) {
            bsl::error() << "vm "                                         // --
                         << bsl::hex(vmid)                                // --
                         << " is the root vm and cannot be destroyed "    // --
                         << bsl::endl                                     // --
                         << bsl::here();                                  // --

            return false;
        }

        auto const vpid{vp_pool.vp_assigned_to_vm(vmid)};
        if (bsl::unlikely(vpid.is_valid())) {
            bsl::error() << "vm "                                 // --
                         << bsl::hex(vmid)                        // --
                         << " cannot be destroyed because vp "    // --
                         << bsl::hex(vpid)                        // --
                         << " is still assigned to this vm"       // --
                         << bsl::endl                             // --
                         << bsl::here();                          // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vp_t associated with the
    ///     provided vpid is destroyable. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vpid the ID of the VP to query
    ///   @return Returns true if the vp_t associated with the
    ///     provided vpid is destroyable. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vp_destroyable(
        syscall::bf_syscall_t const &sys,
        vp_pool_t const &vp_pool,
        vs_pool_t const &vs_pool,
        bsl::safe_u16 const &vpid) noexcept -> bool
    {
        auto const active{vp_pool.is_active(vpid)};
        if (bsl::unlikely(active.is_valid())) {
            bsl::error() << "vp "                         // --
                         << bsl::hex(vpid)                // --
                         << " is active on pp "           // --
                         << bsl::hex(active)              // --
                         << " and cannot be destroyed"    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return false;
        }

        if (bsl::unlikely(sys.is_vp_a_root_vp(vpid))) {
            bsl::error() << "vp "                                       // --
                         << bsl::hex(vpid)                              // --
                         << " is a root vp and cannot be destroyed "    // --
                         << bsl::endl                                   // --
                         << bsl::here();                                // --

            return false;
        }

        auto const vsid{vs_pool.vs_assigned_to_vp(vpid)};
        if (bsl::unlikely(vsid.is_valid())) {
            bsl::error() << "vp "                                 // --
                         << bsl::hex(vpid)                        // --
                         << " cannot be destroyed because vs "    // --
                         << bsl::hex(vsid)                        // --
                         << " is still assigned to this vp"       // --
                         << bsl::endl                             // --
                         << bsl::here();                          // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the vs_t associated with the
    ///     provided vsid is destroyable. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS to query
    ///   @return Returns true if the vs_t associated with the
    ///     provided vsid is destroyable. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vs_destroyable(
        syscall::bf_syscall_t const &sys,
        vs_pool_t const &vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bool
    {
        auto const active{vs_pool.is_active(vsid)};
        if (bsl::unlikely(active.is_valid())) {
            bsl::error() << "vs "                         // --
                         << bsl::hex(vsid)                // --
                         << " is active on pp "           // --
                         << bsl::hex(active)              // --
                         << " and cannot be destroyed"    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return false;
        }

        if (bsl::unlikely(sys.is_vs_a_root_vs(vsid))) {
            bsl::error() << "vs "                                       // --
                         << bsl::hex(vsid)                              // --
                         << " is a root vs and cannot be destroyed "    // --
                         << bsl::endl                                   // --
                         << bsl::here();                                // --

            return false;
        }

        return true;
    }

    /// ------------------------------------------------------------------------
    /// Get Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Given an input register, returns a ppid if the provided
    ///     register contains a valid ppid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param reg the register to get the ppid from.
    ///   @return Given an input register, returns a ppid if the provided
    ///     register contains a valid ppid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_ppid(tls_t const &tls, bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const ppid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == ppid)) {
            bsl::error() << "the provided ppid "                      // --
                         << bsl::hex(ppid)                            // --
                         << " is BF_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(bsl::to_umx(ppid) >= HYPERVISOR_MAX_PPS)) {
            bsl::error() << "the provided ppid "                      // --
                         << bsl::hex(ppid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(ppid >= tls.online_pps)) {
            bsl::error() << "the provided ppid "                   // --
                         << bsl::hex(ppid)                         // --
                         << " is not online and cannot be used"    // --
                         << bsl::endl                              // --
                         << bsl::here();                           // --

            return bsl::safe_u16::failure();
        }

        return ppid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vmid from.
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_vmid(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const vmid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(hypercall::MV_INVALID_ID == vmid)) {
            bsl::error() << "the provided vmid "                      // --
                         << bsl::hex(vmid)                            // --
                         << " is MV_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(bsl::to_umx(vmid) >= HYPERVISOR_MAX_VMS)) {
            bsl::error() << "the provided vmid "                      // --
                         << bsl::hex(vmid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        return vmid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the VM associated with the
    ///     vmid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vmid from.
    ///   @param vm_pool the vm_pool_t to use
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the VM associated with the
    ///     vmid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_allocated_vmid(bsl::safe_u64 const &reg, vm_pool_t const &vm_pool) noexcept -> bsl::safe_u16
    {
        auto const vmid{get_vmid(reg)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const is_deallocated{vm_pool.is_deallocated(vmid)};
        if (bsl::unlikely(is_deallocated)) {
            bsl::error() << "the provided vmid "                         // --
                         << bsl::hex(vmid)                               // --
                         << " was never allocated and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u16::failure();
        }

        return vmid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vpid from.
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_vpid(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const vpid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == vpid)) {
            bsl::error() << "the provided vpid "                      // --
                         << bsl::hex(vpid)                            // --
                         << " is BF_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(bsl::to_umx(vpid) >= HYPERVISOR_MAX_VPS)) {
            bsl::error() << "the provided vpid "                      // --
                         << bsl::hex(vpid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        return vpid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the VM associated with the
    ///     vpid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vpid from.
    ///   @param vp_pool the vp_pool_t to use
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the VM associated with the
    ///     vpid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_allocated_vpid(bsl::safe_u64 const &reg, vp_pool_t const &vp_pool) noexcept -> bsl::safe_u16
    {
        auto const vpid{get_vpid(reg)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const is_deallocated{vp_pool.is_deallocated(vpid)};
        if (bsl::unlikely(is_deallocated)) {
            bsl::error() << "the provided vpid "                         // --
                         << bsl::hex(vpid)                               // --
                         << " was never allocated and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u16::failure();
        }

        return vpid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vsid from.
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_vsid(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const vsid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(syscall::BF_INVALID_ID == vsid)) {
            bsl::error() << "the provided vsid "                      // --
                         << bsl::hex(vsid)                            // --
                         << " is BF_INVALID_ID and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(bsl::to_umx(vsid) >= HYPERVISOR_MAX_VSS)) {
            bsl::error() << "the provided vsid "                      // --
                         << bsl::hex(vsid)                            // --
                         << " is out of bounds and cannot be used"    // --
                         << bsl::endl                                 // --
                         << bsl::here();                              // --

            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the VM associated with the
    ///     vsid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the vsid from.
    ///   @param vs_pool the vs_pool_t to use
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the VM associated with the
    ///     vsid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    // NOLINTNEXTLINE(bsl-non-safe-integral-types-are-forbidden)
    get_allocated_vsid(bsl::safe_u64 const &reg, vs_pool_t const &vs_pool) noexcept -> bsl::safe_u16
    {
        auto const vsid{get_vsid(reg)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const is_deallocated{vs_pool.is_deallocated(vsid)};
        if (bsl::unlikely(is_deallocated)) {
            bsl::error() << "the provided vsid "                         // --
                         << bsl::hex(vsid)                               // --
                         << " was never allocated and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// ------------------------------------------------------------------------
    /// Report Unsupported Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Tells the user that the hypercall is unknown or is not
    ///     supported by MicroV.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @return Always returns vmexit_failure_advance_ip_and_run.
    ///
    [[nodiscard]] constexpr auto
    report_hypercall_unknown_unsupported(syscall::bf_syscall_t &mut_sys) noexcept -> bsl::errc_type
    {
        bsl::error() << "unknown hypercall "                    // --
                     << bsl::hex(get_reg_hypercall(mut_sys))    // --
                     << bsl::endl                               // --
                     << bsl::here();                            // --

        set_reg_return(mut_sys, hypercall::MV_STATUS_FAILURE_UNKNOWN);
        return vmexit_failure_advance_ip_and_run;
    }
}

#endif
