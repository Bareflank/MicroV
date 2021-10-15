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
#include <dispatch_abi_helpers.hpp>
#include <mv_cdl_t.hpp>
#include <mv_reg_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>

namespace microv
{
    /// @brief prototype
    [[nodiscard]] constexpr auto get_gpa(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u64;

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

    /// <!-- description -->
    ///   @brief Returns true if the vs_t associated with the
    ///     provided vsid is assigned to the current PP. Returns false
    ///     otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS to query
    ///   @return Returns true if the vs_t associated with the
    ///     provided vsid is assigned to the current PP. Returns false
    ///     otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_vs_assigned_to_current_pp(
        syscall::bf_syscall_t const &sys,
        vs_pool_t const &vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bool
    {
        auto const assigned_ppid{vs_pool.assigned_pp(vsid)};
        if (bsl::unlikely(assigned_ppid != sys.bf_tls_ppid())) {
            bsl::error() << "vs "                              // --
                         << bsl::hex(vsid)                     // --
                         << " is assigned to pp "              // --
                         << bsl::hex(assigned_ppid)            // --
                         << " which is not the current pp "    // --
                         << bsl::hex(sys.bf_tls_ppid())        // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return false;
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the CDL is safe to use. Returns
    ///     false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param cdl the CDL to verify
    ///   @return Returns true if the CDL is safe to use. Returns
    ///     false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_cdl_safe(hypercall::mv_cdl_t const &cdl) noexcept -> bool
    {
        if (bsl::unlikely(cdl.num_entries == bsl::safe_u64::magic_0())) {
            bsl::error() << "cdl.num_entries "           // --
                         << bsl::hex(cdl.num_entries)    // --
                         << " is empty"                  // --
                         << bsl::endl                    // --
                         << bsl::here();                 // --
            return false;
        }

        if (bsl::unlikely(cdl.num_entries > cdl.entries.size())) {
            bsl::error() << "cdl.num_entries "           // --
                         << bsl::hex(cdl.num_entries)    // --
                         << " is out of range "          // --
                         << bsl::endl                    // --
                         << bsl::here();                 // --
            return false;
        }
        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the RDL is safe to use. Returns
    ///     false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param rdl the RDL to verify
    ///   @return Returns true if the RDL is safe to use. Returns
    ///     false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_rdl_safe(hypercall::mv_rdl_t const &rdl) noexcept -> bool
    {
        if (bsl::unlikely(rdl.num_entries == bsl::safe_u64::magic_0())) {
            bsl::error() << "rdl.num_entries "           // --
                         << bsl::hex(rdl.num_entries)    // --
                         << " is empty"                  // --
                         << bsl::endl                    // --
                         << bsl::here();                 // --
            return false;
        }

        if (bsl::unlikely(rdl.num_entries > rdl.entries.size())) {
            bsl::error() << "rdl.num_entries "           // --
                         << bsl::hex(rdl.num_entries)    // --
                         << " is out of range "          // --
                         << bsl::endl                    // --
                         << bsl::here();                 // --
            return false;
        }
        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the RDL is safe to use. Returns
    ///     false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param rdl the RDL to verify
    ///   @return Returns true if the RDL is safe to use. Returns
    ///     false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_rdl_msr_safe(hypercall::mv_rdl_t const &rdl) noexcept -> bool
    {
        constexpr auto reg0_allowed_mask{~(hypercall::MV_RDL_FLAG_ALL)};
        if (bsl::unlikely((rdl.reg0 & reg0_allowed_mask) != bsl::safe_u64::magic_0())) {
            bsl::error() << "rdl.reg0 "                  // --
                         << bsl::hex(rdl.reg0)           // --
                         << " contains unknown flags"    // --
                         << bsl::endl                    // --
                         << bsl::here();                 // --
            return false;
        }

        if ((rdl.reg0 & hypercall::MV_RDL_FLAG_ALL).is_pos()) {
            if (bsl::unlikely(rdl.num_entries != bsl::safe_u64::magic_0())) {
                bsl::error() << "rdl.num_entries "                             // --
                             << bsl::hex(rdl.num_entries)                      // --
                             << " should be 0 with MV_RDL_FLAG_ALL present"    // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --
                return false;
            }
            bsl::touch();
        }
        else {
            if (bsl::unlikely(rdl.reg1 != bsl::safe_u64::magic_0())) {
                bsl::error() << "rdl.reg1 "                                            // --
                             << bsl::hex(rdl.reg1)                                     // --
                             << " should only be used with MV_RDL_FLAG_ALL present"    // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --
                return false;
            }
            return is_rdl_safe(rdl);
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the MDL is safe to use. Returns
    ///     false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mdl the MDL to verify
    ///   @param unmap if true, the src gpa and flags are ignored. If false,
    ///     everything is verified.
    ///   @return Returns true if the MDL is safe to use. Returns
    ///     false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_mdl_safe(hypercall::mv_mdl_t const &mdl, bool const unmap) noexcept -> bool
    {
        if (bsl::unlikely(mdl.num_entries == bsl::safe_u64::magic_0())) {
            bsl::error() << "mdl.num_entries is empty"    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return false;
        }

        if (bsl::unlikely(mdl.num_entries > mdl.entries.size())) {
            bsl::error() << "mdl.num_entries "           // --
                         << bsl::hex(mdl.num_entries)    // --
                         << " is out of range "          // --
                         << bsl::endl                    // --
                         << bsl::here();                 // --

            return false;
        }

        for (bsl::safe_idx mut_i{}; mut_i < mdl.num_entries; ++mut_i) {
            auto const *const entry{mdl.entries.at_if(mut_i)};

            auto const dst_gpa{get_gpa(bsl::to_u64(entry->dst))};
            if (bsl::unlikely(dst_gpa.is_invalid())) {
                bsl::print<bsl::V>() << bsl::here();
                return false;
            }

            if (!unmap) {
                auto const src_gpa{get_gpa(bsl::to_u64(entry->src))};
                if (bsl::unlikely(src_gpa.is_invalid())) {
                    bsl::print<bsl::V>() << bsl::here();
                    return false;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            auto const bytes{bsl::to_umx(entry->bytes)};
            if (bsl::unlikely(bytes.is_zero())) {
                bsl::error() << "mdl entry "                   // --
                             << mut_i                          // --
                             << " has an empty bytes field"    // --
                             << bsl::endl                      // --
                             << bsl::here();                   // --

                return false;
            }

            if (bsl::unlikely(!hypercall::mv_is_page_aligned(bytes))) {
                bsl::error() << "mdl entry "             // --
                             << mut_i                    // --
                             << " has a bytes field "    // --
                             << bsl::hex(bytes)          // --
                             << " that is unaligned"     // --
                             << bsl::endl                // --
                             << bsl::here();             // --

                return false;
            }

            if (bsl::unlikely(bytes >= MICROV_MAX_GPA_SIZE)) {
                bsl::error() << "mdl entry "               // --
                             << mut_i                      // --
                             << " has a bytes field "      // --
                             << bsl::hex(bytes)            // --
                             << " that is out of range"    // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return false;
            }

            if (bsl::unlikely(bytes != HYPERVISOR_PAGE_SIZE)) {
                bsl::error() << "mdl entry "                                              // --
                             << mut_i                                                     // --
                             << " has a bytes field "                                     // --
                             << bsl::hex(bytes)                                           // --
                             << " that is compressed which is currently not supported"    // --
                             << bsl::endl                                                 // --
                             << bsl::here();                                              // --

                return false;
            }

            if (!unmap) {

                /// TODO:
                /// - Verify the flags field.
                ///

                bsl::touch();
            }
            else {
                bsl::touch();
            }
        }

        return true;
    }

    /// <!-- description -->
    ///   @brief Returns true if the provided TSC frequency was properly
    ///     set. Returns false otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param tsc_khz the TSC frequency to verify
    ///   @return Returns true if the provided TSC frequency was properly
    ///     set. Returns false otherwise.
    ///
    [[nodiscard]] constexpr auto
    is_tsc_khz_set(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &tsc_khz) noexcept -> bool
    {
        if (bsl::unlikely(tsc_khz.is_zero())) {
            bsl::error() << "the tsc frequency for pp "    // --
                         << bsl::hex(sys.bf_tls_ppid())    // --
                         << " was never set"               // --
                         << bsl::endl                      // --
                         << bsl::here();                   // --

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
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the ppid from.
    ///   @return Given an input register, returns a ppid if the provided
    ///     register contains a valid ppid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_ppid(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const ppid{bsl::to_u16_unsafe(reg)};
        if (ppid == hypercall::MV_SELF_ID) {
            return sys.bf_tls_ppid();
        }

        if (bsl::unlikely(hypercall::MV_INVALID_ID == ppid)) {
            bsl::error() << "the provided ppid "                      // --
                         << bsl::hex(ppid)                            // --
                         << " is MV_INVALID_ID and cannot be used"    // --
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

        if (bsl::unlikely(ppid >= sys.bf_tls_online_pps())) {
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
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vmid from.
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_vmid(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const vmid{bsl::to_u16_unsafe(reg)};
        if (hypercall::MV_SELF_ID == vmid) {
            return sys.bf_tls_vmid();
        }

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
    ///     register contains a valid vmid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vmid from.
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_non_self_vmid(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &reg) noexcept
        -> bsl::safe_u16
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

        if (bsl::unlikely(hypercall::MV_SELF_ID == vmid)) {
            bsl::error() << "the provided vmid "                     // --
                         << bsl::hex(vmid)                           // --
                         << " is MV_SELF_ID which cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_u16::failure();
        }

        auto const self{sys.bf_tls_vmid()};
        if (bsl::unlikely(self == vmid)) {
            bsl::error() << "the provided vmid "                     // --
                         << bsl::hex(hypercall::MV_SELF_ID)          // --
                         << " is MV_SELF_ID which cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_u16::failure();
        }

        return vmid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the vm_t associated with the
    ///     vmid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vmid from.
    ///   @param vm_pool the vm_pool_t to use
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the vm_t associated with the
    ///     vmid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_vmid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vm_pool_t const &vm_pool) noexcept -> bsl::safe_u16
    {
        auto const vmid{get_vmid(sys, reg)};
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
    ///   @brief Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the vm_t associated with the
    ///     vmid is allocated and not self. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vmid from.
    ///   @param vm_pool the vm_pool_t to use
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the vm_t associated with the
    ///     vmid is allocated and not self. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_non_self_vmid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vm_pool_t const &vm_pool) noexcept -> bsl::safe_u16
    {
        auto const vmid{get_non_self_vmid(sys, reg)};
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
    ///   @brief Given an input register, returns a vmid if the provided
    ///     register contains a valid root vmid. Otherwise, this function
    ///     returns bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vmid from.
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid root vmid. Otherwise, this function
    ///     returns bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_root_vmid(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &reg) noexcept
        -> bsl::safe_u16
    {
        auto mut_vmid{bsl::to_u16_unsafe(reg)};
        if (hypercall::MV_SELF_ID == mut_vmid) {
            mut_vmid = sys.bf_tls_vmid();
        }
        else {
            bsl::touch();
        }

        if (bsl::unlikely(mut_vmid != hypercall::MV_ROOT_VMID)) {
            bsl::error() << "the provided vmid "                        // --
                         << bsl::hex(mut_vmid)                          // --
                         << " is not the root vm and cannot be used"    // --
                         << bsl::endl                                   // --
                         << bsl::here();                                // --

            return bsl::safe_u16::failure();
        }

        return mut_vmid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the vm_t associated with the
    ///     vmid is allocated and is not the root vm_t. Otherwise, this
    ///     function returns bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vmid from.
    ///   @param vm_pool the vm_pool_t to use
    ///   @return Given an input register, returns a vmid if the provided
    ///     register contains a valid vmid and the vm_t associated with the
    ///     vmid is allocated and is not the root vm_t. Otherwise, this
    ///     function returns bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_guest_vmid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vm_pool_t const &vm_pool) noexcept -> bsl::safe_u16
    {
        auto const vmid{get_allocated_vmid(sys, reg, vm_pool)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(vmid == hypercall::MV_ROOT_VMID)) {
            bsl::error() << "the provided vmid "                    // --
                         << bsl::hex(vmid)                          // --
                         << " is the root vm and cannot be used"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

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
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vpid from.
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_vpid(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const vpid{bsl::to_u16_unsafe(reg)};
        if (hypercall::MV_SELF_ID == vpid) {
            return sys.bf_tls_vpid();
        }

        if (bsl::unlikely(hypercall::MV_INVALID_ID == vpid)) {
            bsl::error() << "the provided vpid "                      // --
                         << bsl::hex(vpid)                            // --
                         << " is MV_INVALID_ID and cannot be used"    // --
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
    ///     register contains a valid vpid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vpid from.
    ///   @param vp_pool the vp_pool_t to use
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_non_self_vpid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vp_pool_t const &vp_pool) noexcept -> bsl::safe_u16
    {
        auto const vpid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(hypercall::MV_INVALID_ID == vpid)) {
            bsl::error() << "the provided vpid "                      // --
                         << bsl::hex(vpid)                            // --
                         << " is MV_INVALID_ID and cannot be used"    // --
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

        if (bsl::unlikely(hypercall::MV_SELF_ID == vpid)) {
            bsl::error() << "the provided vpid "                     // --
                         << bsl::hex(vpid)                           // --
                         << " is MV_SELF_ID which cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_u16::failure();
        }

        auto const self{sys.bf_tls_vpid()};
        if (bsl::unlikely(self == vpid)) {
            bsl::error() << "the provided vpid "                     // --
                         << bsl::hex(vpid)                           // --
                         << " is MV_SELF_ID which cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_u16::failure();
        }

        auto const self_vmid{vp_pool.assigned_vm(self)};
        if (bsl::unlikely(self_vmid == vp_pool.assigned_vm(vpid))) {
            bsl::error() << "the provided vpid "               // --
                         << bsl::hex(vpid)                     // --
                         << " is assigned to the same vm "     // --
                         << bsl::hex(self_vmid)                // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return bsl::safe_u16::failure();
        }

        return vpid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the vp_t associated with the
    ///     vpid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vpid from.
    ///   @param vp_pool the vp_pool_t to use
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the vp_t associated with the
    ///     vpid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_vpid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vp_pool_t const &vp_pool) noexcept -> bsl::safe_u16
    {
        auto const vpid{get_vpid(sys, reg)};
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
    ///   @brief Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the vp_t associated with the
    ///     vpid is allocated and not self. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vpid from.
    ///   @param vp_pool the vp_pool_t to use
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the vp_t associated with the
    ///     vpid is allocated and not self. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_non_self_vpid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vp_pool_t const &vp_pool) noexcept -> bsl::safe_u16
    {
        auto const vpid{get_non_self_vpid(sys, reg, vp_pool)};
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
    ///   @brief Given an input register, returns a vpid if the provided
    ///     register contains a valid root vpid. Otherwise, this function
    ///     returns bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vpid from.
    ///   @param vp_pool the vp_pool_t to use
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid root vpid. Otherwise, this function
    ///     returns bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_root_vpid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vp_pool_t const &vp_pool) noexcept -> bsl::safe_u16
    {
        auto const vpid{get_allocated_vpid(sys, reg, vp_pool)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(!sys.is_vp_a_root_vp(vpid))) {
            bsl::error() << "the provided vpid "                        // --
                         << bsl::hex(vpid)                              // --
                         << " is not the root vp and cannot be used"    // --
                         << bsl::endl                                   // --
                         << bsl::here();                                // --

            return bsl::safe_u16::failure();
        }

        return vpid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the vp_t associated with the
    ///     vpid is allocated and is not the root vp_t. Otherwise, this
    ///     function returns bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vpid from.
    ///   @param vp_pool the vp_pool_t to use
    ///   @return Given an input register, returns a vpid if the provided
    ///     register contains a valid vpid and the vp_t associated with the
    ///     vpid is allocated and is not the root vp_t. Otherwise, this
    ///     function returns bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_guest_vpid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vp_pool_t const &vp_pool) noexcept -> bsl::safe_u16
    {
        auto const vpid{get_allocated_vpid(sys, reg, vp_pool)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(sys.is_vp_a_root_vp(vpid))) {
            bsl::error() << "the provided vpid "                    // --
                         << bsl::hex(vpid)                          // --
                         << " is the root vp and cannot be used"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

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
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vsid from.
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_vsid(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &reg) noexcept -> bsl::safe_u16
    {
        auto const vsid{bsl::to_u16_unsafe(reg)};
        if (hypercall::MV_SELF_ID == vsid) {
            return sys.bf_tls_vsid();
        }

        if (bsl::unlikely(hypercall::MV_INVALID_ID == vsid)) {
            bsl::error() << "the provided vsid "                      // --
                         << bsl::hex(vsid)                            // --
                         << " is MV_INVALID_ID and cannot be used"    // --
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
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param sys the bf_syscall_t to use
    ///   @param reg the register to get the vsid from.
    ///   @param vs_pool the vs_pool_t to use
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_non_self_vsid(
        syscall::bf_syscall_t const &sys,
        bsl::safe_u64 const &reg,
        vs_pool_t const &vs_pool) noexcept -> bsl::safe_u16
    {
        auto const vsid{bsl::to_u16_unsafe(reg)};
        if (bsl::unlikely(hypercall::MV_INVALID_ID == vsid)) {
            bsl::error() << "the provided vsid "                      // --
                         << bsl::hex(vsid)                            // --
                         << " is MV_INVALID_ID and cannot be used"    // --
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

        if (bsl::unlikely(hypercall::MV_SELF_ID == vsid)) {
            bsl::error() << "the provided vsid "                     // --
                         << bsl::hex(vsid)                           // --
                         << " is MV_SELF_ID which cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_u16::failure();
        }

        auto const self{sys.bf_tls_vsid()};
        if (bsl::unlikely(self == vsid)) {
            bsl::error() << "the provided vsid "                     // --
                         << bsl::hex(hypercall::MV_SELF_ID)          // --
                         << " is MV_SELF_ID which cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_u16::failure();
        }

        auto const self_vmid{vs_pool.assigned_vm(self)};
        if (bsl::unlikely(self_vmid == vs_pool.assigned_vm(vsid))) {
            bsl::error() << "the provided vsid "               // --
                         << bsl::hex(vsid)                     // --
                         << " is assigned to the same vm "     // --
                         << bsl::hex(self_vmid)                // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the vs_t associated with the
    ///     vsid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param reg the register to get the vsid from.
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the vs_t associated with the
    ///     vsid is allocated. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_vsid(
        syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &reg, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::safe_u16
    {
        auto const vsid{get_vsid(mut_sys, reg)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const is_deallocated{mut_vs_pool.is_deallocated(vsid)};
        if (bsl::unlikely(is_deallocated)) {
            bsl::error() << "the provided vsid "                         // --
                         << bsl::hex(vsid)                               // --
                         << " was never allocated and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u16::failure();
        }

        auto const ret{mut_vs_pool.migrate(mut_sys, vsid)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the vs_t associated with the
    ///     vsid is allocated and not self. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param reg the register to get the vsid from.
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the vs_t associated with the
    ///     vsid is allocated and not self. Otherwise, this function returns
    ///     bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_non_self_vsid(
        syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &reg, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::safe_u16
    {
        auto const vsid{get_non_self_vsid(mut_sys, reg, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        bool const is_deallocated{mut_vs_pool.is_deallocated(vsid)};
        if (bsl::unlikely(is_deallocated)) {
            bsl::error() << "the provided vsid "                         // --
                         << bsl::hex(vsid)                               // --
                         << " was never allocated and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u16::failure();
        }

        auto const ret{mut_vs_pool.migrate(mut_sys, vsid)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid root vsid. Otherwise, this function
    ///     returns bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param reg the register to get the vsid from.
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid root vsid. Otherwise, this function
    ///     returns bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_root_vsid(
        syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &reg, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::safe_u16
    {
        auto const vsid{get_allocated_vsid(mut_sys, reg, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(!mut_sys.is_vs_a_root_vs(vsid))) {
            bsl::error() << "the provided vsid "                        // --
                         << bsl::hex(vsid)                              // --
                         << " is not the root vs and cannot be used"    // --
                         << bsl::endl                                   // --
                         << bsl::here();                                // --

            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the vs_t associated with the
    ///     vsid is allocated and is not the root vs_t. Otherwise, this
    ///     function returns bsl::safe_u16::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param reg the register to get the vsid from.
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Given an input register, returns a vsid if the provided
    ///     register contains a valid vsid and the vs_t associated with the
    ///     vsid is allocated and is not the root vs_t. Otherwise, this
    ///     function returns bsl::safe_u16::failure().
    ///
    [[nodiscard]] constexpr auto
    get_allocated_guest_vsid(
        syscall::bf_syscall_t &mut_sys, bsl::safe_u64 const &reg, vs_pool_t &mut_vs_pool) noexcept
        -> bsl::safe_u16
    {
        auto const vsid{get_allocated_vsid(mut_sys, reg, mut_vs_pool)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u16::failure();
        }

        if (bsl::unlikely(mut_sys.is_vs_a_root_vs(vsid))) {
            bsl::error() << "the provided vsid "                    // --
                         << bsl::hex(vsid)                          // --
                         << " is the root vs and cannot be used"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            return bsl::safe_u16::failure();
        }

        return vsid;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a guest linear address if
    ///     the provided register contains a valid guest linear address.
    ///     Otherwise, this function returns bsl::safe_u64::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the guest linear address from.
    ///   @return Given an input register, returns a guest linear address if
    ///     the provided register contains a valid guest linear address.
    ///     Otherwise, this function returns bsl::safe_u64::failure().
    ///
    [[nodiscard]] constexpr auto
    get_gla(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u64
    {
        /// TODO:
        /// - Add a canonical address check here. This also needs to be added
        ///   to the hypervisor's get_virt function.
        /// - Add a physical address check that uses CPUID to determine if a
        ///   physical address is valid. The max physical address should be
        ///   cached in the TLS so that it can be used. This should be added
        ///   to a get_gpa, and get_phys function in the hypervisor.
        ///

        auto const gla{bsl::to_u64(reg)};
        if (bsl::unlikely(gla.is_zero())) {
            bsl::error() << "the guest linear address "                // --
                         << bsl::hex(gla)                              // --
                         << " is a NULL address and cannot be used"    // --
                         << bsl::endl                                  // --
                         << bsl::here();                               // --

            return bsl::safe_u64::failure();
        }

        bool const aligned{hypercall::mv_is_page_aligned(gla)};
        if (bsl::unlikely(!aligned)) {
            bsl::error() << "the guest linear address "                  // --
                         << bsl::hex(gla)                                // --
                         << " is not page aligned and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u64::failure();
        }

        return gla;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a guest physical address if
    ///     the provided register contains a valid guest physical address.
    ///     Otherwise, this function returns bsl::safe_u64::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the physical address from.
    ///   @return Given an input register, returns a guest physical address if
    ///     the provided register contains a valid guest physical address.
    ///     Otherwise, this function returns bsl::safe_u64::failure().
    ///
    [[nodiscard]] constexpr auto
    get_gpa(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u64
    {
        auto const gpa{bsl::to_u64(reg)};
        if (bsl::unlikely(gpa >= MICROV_MAX_GPA_SIZE)) {
            bsl::error() << "the guest physical address "            // --
                         << bsl::hex(gpa)                            // --
                         << " is out of range and cannot be used"    // --
                         << bsl::endl                                // --
                         << bsl::here();                             // --

            return bsl::safe_u64::failure();
        }

        bool const aligned{syscall::bf_is_page_aligned(gpa)};
        if (bsl::unlikely(!aligned)) {
            bsl::error() << "the guest physical address "                // --
                         << bsl::hex(gpa)                                // --
                         << " is not page aligned and cannot be used"    // --
                         << bsl::endl                                    // --
                         << bsl::here();                                 // --

            return bsl::safe_u64::failure();
        }

        return gpa;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a guest physical address if
    ///     the provided register contains a valid guest physical address
    ///     that is non-NULL. Otherwise, this function returns
    ///     bsl::safe_u64::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the physical address from.
    ///   @return Given an input register, returns a guest physical address if
    ///     the provided register contains a valid guest physical address
    ///     that is non-NULL. Otherwise, this function returns
    ///     bsl::safe_u64::failure().
    ///
    [[nodiscard]] constexpr auto
    get_pos_gpa(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u64
    {
        auto const gpa{get_gpa(reg)};
        if (bsl::unlikely(gpa.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::safe_u64::failure();
        }

        if (bsl::unlikely(gpa.is_zero())) {
            bsl::error() << "the guest physical address "    // --
                         << bsl::hex(gpa)                    // --
                         << " is NULL and cannot be used"    // --
                         << bsl::endl                        // --
                         << bsl::here();                     // --

            return bsl::safe_u64::failure();
        }

        return gpa;
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a mv_mp_state_t if
    ///     the provided register contains a valid mv_mp_state_t
    ///     that is in range and supported. Otherwise, this function returns
    ///     bsl::safe_u64::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the TSC frequency from.
    ///   @return Given an input register, returns a mv_mp_state_t if
    ///     the provided register contains a valid mv_mp_state_t
    ///     that is in range and supported. Otherwise, this function returns
    ///     bsl::safe_u64::failure().
    ///
    [[nodiscard]] constexpr auto
    get_mp_state(bsl::safe_u64 const &reg) noexcept -> hypercall::mv_mp_state_t
    {
        if (bsl::unlikely(reg >= bsl::to_u64(hypercall::MP_STATE_INVALID))) {
            bsl::error() << "mp_state "                          // --
                         << bsl::hex(reg)                        // --
                         << " is out of range or unsupported"    // --
                         << bsl::endl                            // --
                         << bsl::here();                         // --

            return hypercall::mv_mp_state_t::mv_mp_state_t_invalid;
        }

        return hypercall::to_mv_mp_state_t(reg);
    }

    /// <!-- description -->
    ///   @brief Given an input register, returns a TSC frequency in KHz if
    ///     the provided register contains a valid TSC frequency in KHz
    ///     that is non-0. Otherwise, this function returns
    ///     bsl::safe_u64::failure().
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg the register to get the TSC frequency from.
    ///   @return Given an input register, returns a TSC frequency in KHz if
    ///     the provided register contains a valid TSC frequency in KHz
    ///     that is non-0. Otherwise, this function returns
    ///     bsl::safe_u64::failure().
    ///
    [[nodiscard]] constexpr auto
    get_tsc_khz(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u64
    {
        auto const tsc_khz{reg};
        if (bsl::unlikely(tsc_khz.is_zero())) {
            bsl::error() << "the tsc frequency "          // --
                         << bsl::hex(tsc_khz)             // --
                         << " is 0 and cannot be used"    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return bsl::safe_u64::failure();
        }

        return tsc_khz;
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

    /// ------------------------------------------------------------------------
    /// Run/Switch Functions
    /// ------------------------------------------------------------------------

    /// <!-- description -->
    ///   @brief Run's a guest vs_t. When a guest VM is run, it becomes a
    ///     child, and the current VM, VP and VS become parents. The next
    ///     time that MicroV executes, it will be from the VMExit handler.
    ///     The VMExit handler can execute for any VS, including a root VS,
    ///     but when the next VMExit occurs on the PP that runs this
    ///     function, it will be for the child VS. This function must also
    ///     save/load state that is not handled by the Microkernel, as a
    ///     new VS is being run.
    ///
    /// <!-- notes -->
    ///   @note This function does not return
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS to run
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    run_guest(
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        bsl::expects(!mut_sys.is_vs_a_root_vs(vsid));
        bsl::expects(mut_tls.parent_vmid == hypercall::MV_INVALID_ID);
        bsl::expects(mut_tls.parent_vpid == hypercall::MV_INVALID_ID);
        bsl::expects(mut_tls.parent_vsid == hypercall::MV_INVALID_ID);

        auto const vmid{mut_vs_pool.assigned_vm(vsid)};
        auto const vpid{mut_vs_pool.assigned_vp(vsid)};

        auto const vp_active{mut_vp_pool.is_active(vpid)};
        if (bsl::unlikely(!vp_active.is_invalid())) {
            bsl::error() << "vp "                              // --
                         << bsl::hex(vpid)                     // --
                         << " is already active on PP "        // --
                         << bsl::hex(vp_active)                // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return bsl::errc_failure;
        }

        auto const vs_active{mut_vs_pool.is_active(vsid)};
        if (bsl::unlikely(!vs_active.is_invalid())) {
            bsl::error() << "vs "                              // --
                         << bsl::hex(vsid)                     // --
                         << " is already active on PP "        // --
                         << bsl::hex(vs_active)                // --
                         << " and therefore cannot be used"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return bsl::errc_failure;
        }

        mut_tls.parent_vmid = mut_sys.bf_tls_vmid();
        mut_tls.parent_vpid = mut_sys.bf_tls_vpid();
        mut_tls.parent_vsid = mut_sys.bf_tls_vsid();

        mut_vm_pool.set_inactive(mut_tls, mut_tls.parent_vmid);
        mut_vp_pool.set_inactive(mut_tls, mut_tls.parent_vpid);
        mut_vs_pool.set_inactive(mut_tls, intrinsic, mut_tls.parent_vsid);

        bsl::expects(mut_sys.bf_vs_op_set_active(vmid, vpid, vsid));

        mut_vm_pool.set_active(mut_tls, vmid);
        mut_vp_pool.set_active(mut_tls, vpid);
        mut_vs_pool.set_active(mut_tls, intrinsic, vsid);

        bsl::expects(mut_vs_pool.mp_state_set(
            mut_sys, hypercall::mv_mp_state_t::mv_mp_state_t_running, vsid));

        return mut_sys.bf_vs_op_run_current();
    }

    /// <!-- description -->
    ///   @brief When a VMExit occurs, the active VM, VP and VS are either
    ///     from the root or a guest. The microkernel has this idea of the
    ///     "active" resource. If you use sys.bf_vs_op_read or
    ///     sys.bf_vs_op_write, you provide a VSID, which means not matter
    ///     who is active, these reads/writes work as expected. The TLS
    ///     functions like sys.bf_tls_rax, are based on the active VS. These
    ///     functions read/write state a LOT faster than the functions listed
    ///     above because they do not execute a syscall, and instead simply
    ///     read/write to TLS variables that the Microkernel will save/load
    ///     when the active VS is changed.
    ///
    ///     So what this means is that when a VMExit occurs for a guest,
    ///     the TLS functions read/write the guest VS that generated the
    ///     VMExit. But, in some cases, you will need to return to the
    ///     root VM so that it can handle the VMExit from userspace. The
    ///     problem is, the "active" VS is the guest VS. To solve this, we
    ///     use this function. It is the other half to run_guest.
    ///
    ///     If a VMExit occurs where we simply need to emulate an instruction
    ///     and return, we call sys.bf_vs_op_run_current (or the advance IP
    ///     version of it). This tells the Microkernel, to run the active VS
    ///     which is really fast as there is a lot of checking that must take
    ///     place. If, however, the root VM should handle the exit, we need
    ///     to return to the root. This requires us to change the state of
    ///     the PP. So the pattern is this:
    ///     - run_guest
    ///     - VMExit
    ///     - switch_to_root
    ///     - bf_vs_op_run_current
    ///
    ///     What this is doing is running a guest VS. The next VMExit will
    ///     have the guest VS set to active. We then gather state from the
    ///     VS, and switch to the root. This sets the root VS as the active
    ///     VS. Now, read/writes to the TLS functions will be for the root
    ///     VS and not the guest VS. Once we are done loading the root VS
    ///     state with the guest state that the root will need to handle the
    ///     VMExit, we run bf_vs_op_run_current. This is because we have set
    ///     the root VS as active, so the current VS is the root VS. VMExits
    ///     that do not need to change the active VS look more like this
    ///     - VMExit
    ///     - emulate instruction
    ///     - bf_vs_op_run_current
    ///
    ///     Advancing the IP is also important. Remember that we have both
    ///     a guest VS and a root VS to worry about if this function is to
    ///     be executed. Lets look at a simple example.
    ///     - root VS calls mv_vs_op_run to executed a guest VS.
    ///     - guest executes until a PIO instruction is seen
    ///     - VMExit occurs for guest VS
    ///     - MicroV gathers state associated with the PIO
    ///     - root VS is executed to handle the PIO
    ///     - root VS calls mv_vs_op_run to executed a guest VS.
    ///     - ...
    ///
    ///     The PIO that generated the exit is going to be emulated by the
    ///     root VS. When it returns, the VS's IP should be advanced to the
    ///     next instruction. The root VS must also have been advanced. This
    ///     is because the call to run the guest VS in the first place was
    ///     a vmcall (and friends) instruction, and when we return to the
    ///     root VS, we need to return to the next instruction as well.
    ///
    ///     What this means is that there are TWO IPs that we need to worry
    ///     about. The IP of the root and guest VS. The "advance_ip" param
    ///     for this function call handles the guest VS. If set to true,
    ///     just before the active VS is switch from the guest VS to the
    ///     root VS, the IP of the guest VS is advanced. Then the active VS
    ///     is changed to the root VS. To advance the IP of the root VS,
    ///     all you need to do is us bf_vs_op_advance_ip_and_run_current.
    ///     So the patten for handling PIO for example would be:
    ///     - VMExit
    ///     - Gather guest VS state
    ///     - switch_to_root
    ///     - Set the root VS state so that the root VS has what it needs
    ///       to emulate the PIO
    ///     - bf_vs_op_advance_ip_and_run_current, which advances the IP
    ///       of the root VS (since it is the active VS now), which means
    ///       the next instruction after the VMCall that started the guest
    ///       in the first place is now executed, and then the root VS is
    ///       actually run.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param advance_ip if true, the IP of the guest is advanced before
    ///     we switch to the root. If false, not IP advancement takes
    ///     place here.
    ///
    constexpr void
    switch_to_root(
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bool const advance_ip) noexcept
    {
        bsl::expects(!mut_sys.is_the_active_vm_the_root_vm());
        bsl::expects(mut_tls.parent_vmid != hypercall::MV_INVALID_ID);
        bsl::expects(mut_tls.parent_vpid != hypercall::MV_INVALID_ID);
        bsl::expects(mut_tls.parent_vsid != hypercall::MV_INVALID_ID);

        auto const vmid{mut_sys.bf_tls_vmid()};
        auto const vpid{mut_sys.bf_tls_vpid()};
        auto const vsid{mut_sys.bf_tls_vsid()};

        mut_vm_pool.set_inactive(mut_tls, vmid);
        mut_vp_pool.set_inactive(mut_tls, vpid);
        mut_vs_pool.set_inactive(mut_tls, intrinsic, vsid);

        if (advance_ip) {
            bsl::expects(mut_sys.bf_vs_op_advance_ip_and_set_active(
                mut_tls.parent_vmid, mut_tls.parent_vpid, mut_tls.parent_vsid));
        }
        else {
            bsl::expects(mut_sys.bf_vs_op_set_active(
                mut_tls.parent_vmid, mut_tls.parent_vpid, mut_tls.parent_vsid));
        }

        mut_vm_pool.set_active(mut_tls, mut_tls.parent_vmid);
        mut_vp_pool.set_active(mut_tls, mut_tls.parent_vpid);
        mut_vs_pool.set_active(mut_tls, intrinsic, mut_tls.parent_vsid);

        mut_tls.parent_vmid = hypercall::MV_INVALID_ID;
        mut_tls.parent_vpid = hypercall::MV_INVALID_ID;
        mut_tls.parent_vsid = hypercall::MV_INVALID_ID;
    }

    /// <!-- description -->
    ///   @brief Returns from a VMExit.
    ///
    /// <!-- notes -->
    ///   @note This function does not return unless the provided error
    ///     code is not one that can be handled.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    return_unknown(
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool) noexcept -> bsl::errc_type
    {
        if (mut_sys.is_the_active_vm_the_root_vm()) {
            if (!mut_tls.handling_vmcall) {
                bsl::error() << "unrecoverable error from the root VM\n" << bsl::here();
                return bsl::errc_failure;
            }

            set_reg_return(mut_sys, hypercall::MV_STATUS_EXIT_UNKNOWN);
            set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_UNKNOWN));

            return mut_sys.bf_vs_op_advance_ip_and_run_current();
        }

        /// NOTE:
        /// - If we get this far, it is because we are executing right now
        ///   from the context of a guest VM. This means that right now, all
        ///   of the TLS registers point to registers in the guest VS. It
        ///   also means that in the root VM, the IP points to the vmcall
        ///   instruction that was called when mv_vs_op_run was called. This
        ///   is because the ONLY way that a guest VM would have been running
        ///   is if the root VM asked MicroV to run it using this hypercall.
        ///
        /// - This means that no matter how we got to this pointer, whether
        ///   it is because of a crash, segfault, error, narrow contract
        ///   violation, whatever, we know that at the very least, the root
        ///   VM is still there, and the IP points to the vmcall for this
        ///   hypercall. So, to recover, all we need to do is go back to the
        ///   root VM.
        ///
        /// - To do this we need to switch the the root VM's context. Again,
        ///   right now we are in the guest VM's context. But we want to
        ///   return an error, but that means we need a way to modify the
        ///   registers for the root VM, not the guest VM. To handle this,
        ///   we switch to the root VM. This ensures that the state of the
        ///   root VM is now loaded and ready for us to use.
        ///
        /// - Finally, we tell the root VM that there was an error, and we
        ///   run the root VM, but advance the IP because we want to execute
        ///   just after the vmcall.
        ///

        // ---------------------------------------------------------------------
        // Context: Change To Root VM
        // ---------------------------------------------------------------------

        switch_to_root(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool, false);

        // ---------------------------------------------------------------------
        // Context: Root VM
        // ---------------------------------------------------------------------

        set_reg_return(mut_sys, hypercall::MV_STATUS_EXIT_UNKNOWN);
        set_reg0(mut_sys, bsl::to_u64(hypercall::EXIT_REASON_UNKNOWN));

        return mut_sys.bf_vs_op_advance_ip_and_run_current();
    }

    /// <!-- description -->
    ///   @brief Returns from a VMExit.
    ///
    /// <!-- notes -->
    ///   @note This function does not return unless the provided error
    ///     code is not one that can be handled.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param vsid the ID of the VS to return from
    ///   @param errc the return code from the VMExit handlers.
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] constexpr auto
    return_from_vmexit(
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &vsid,
        bsl::errc_type const &errc) noexcept -> bsl::errc_type
    {
        switch (errc.get()) {
            case vmexit_success_run.get(): {
                return mut_sys.bf_vs_op_run_current();
            }

            case vmexit_success_advance_ip_and_run.get(): {
                return mut_sys.bf_vs_op_advance_ip_and_run_current();
            }

            case vmexit_success_promote.get(): {
                return mut_sys.bf_vs_op_promote(vsid);
            }

            case vmexit_failure_run.get(): {
                bsl::print<bsl::V>() << bsl::here();
                return mut_sys.bf_vs_op_run_current();
            }

            case vmexit_failure_advance_ip_and_run.get(): {
                bsl::print<bsl::V>() << bsl::here();
                return mut_sys.bf_vs_op_advance_ip_and_run_current();
            }

            default: {
                bsl::print<bsl::V>() << bsl::here();
                break;
            }
        }

        return return_unknown(mut_tls, mut_sys, intrinsic, mut_vm_pool, mut_vp_pool, mut_vs_pool);
    }
}

#endif
