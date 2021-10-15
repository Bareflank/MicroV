/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <debug.h>
#include <detect_hypervisor.h>
#include <g_mut_hndl.h>
#include <kvm_userspace_memory_region.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_mdl_t.h>
#include <mv_types.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vm_t.h>

/**
 * <!-- description -->
 *   @brief Returns the slot "ID" given the slot value from
 *     usespace for KVM_SET_USER_MEMORY_REGION
 *
 * <!-- inputs/outputs -->
 *   @param slot the slot to parse
 *   @return Returns the slot "ID" given the slot value from
 *     usespace for KVM_SET_USER_MEMORY_REGION
 */
NODISCARD static inline uint32_t
get_slot_id(uint32_t const slot) NOEXCEPT
{
    uint32_t const id_mask = 0x0000FFFFU;
    return slot & id_mask;
}

/**
 * <!-- description -->
 *   @brief Returns the slot "address space" given the slot value from
 *     usespace for KVM_SET_USER_MEMORY_REGION
 *
 * <!-- inputs/outputs -->
 *   @param slot the slot to parse
 *   @return Returns the slot "address space" given the slot value from
 *     usespace for KVM_SET_USER_MEMORY_REGION
 */
NODISCARD static inline uint32_t
get_slot_as(uint32_t const slot) NOEXCEPT
{
    uint32_t const as_mask = 0xFFFF0000U;
    return slot & as_mask;
}

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_set_user_memory_region.
 *
 * <!-- inputs/outputs -->
 *   @param args the arguments provided by userspace
 *   @param pmut_vm pmut_vm the VM to modify
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vm_kvm_set_user_memory_region(
    struct kvm_userspace_memory_region const *const args, struct shim_vm_t *const pmut_vm) NOEXCEPT
{
    struct mv_mdl_t *pmut_mut_mdl;

    int64_t mut_i;
    int64_t mut_size;

    uint32_t mut_slot_id;
    uint32_t mut_slot_as;
    uint64_t mut_dst;
    uint64_t mut_src;

    platform_expects(NULL != args);
    platform_expects(NULL != pmut_vm);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return SHIM_FAILURE;
    }

    pmut_mut_mdl = (struct mv_mdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_mut_mdl);

    mut_slot_id = get_slot_id(args->slot);
    mut_slot_as = get_slot_as(args->slot);
    mut_dst = args->guest_phys_addr;
    mut_src = args->userspace_addr;
    mut_size = (int64_t)args->memory_size;

    if (!mv_is_page_aligned(args->memory_size)) {
        mut_size += HYPERVISOR_PAGE_SIZE;
        mut_size &= ~(HYPERVISOR_PAGE_SIZE - ((uint64_t)1));
    }
    else {
        mv_touch();
    }

    if (args->memory_size > (uint64_t)INT64_MAX) {
        bferror("args->memory_size is out of bounds");
        return SHIM_FAILURE;
    }

    if (((uint64_t)0) == args->memory_size) {
        bferror("deleting an existing slot is currently not implemeneted");
        return SHIM_FAILURE;
    }

    if (!mv_is_page_aligned(args->guest_phys_addr)) {
        bferror("args->guest_phys_addr is not 4k page aligned");
        return SHIM_FAILURE;
    }

    if (args->guest_phys_addr > MICROV_MAX_GPA_SIZE) {
        bferror("args->guest_phys_addr is out of bounds");
        return SHIM_FAILURE;
    }

    if (!mv_is_page_aligned(args->userspace_addr)) {
        bferror("args->userspace_addr is not 4k page aligned");
        return SHIM_FAILURE;
    }

    if (((uint64_t)0) == args->userspace_addr) {
        bferror("args->userspace_addr is NULL");
        return SHIM_FAILURE;
    }

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

    if ((uint64_t)mut_slot_id >= MICROV_MAX_SLOTS) {
        bferror("args->slot is out of bounds");
        return SHIM_FAILURE;
    }

    if (mut_slot_as > ((uint32_t)0)) {
        bferror("KVM_CAP_MULTI_ADDRESS_SPACE is currently not supported");
        return SHIM_FAILURE;
    }

    platform_mutex_lock(&pmut_vm->mutex);
    if (((uint64_t)0) != pmut_vm->slots[mut_slot_id].memory_size) {

        /// NOTE:
        /// - Only add support for this if it is actually something that
        ///   QEMU or rust-vmm are doing. Likely, slots will be modified
        ///   during migration, but outside of that, slots should be
        ///   static, so hopefully this is never needed.
        ///
        /// - The reason that we don't want to do this is it will require
        ///   that we run mv_vm_op_mmio_unmap. This function is simple
        ///   enough except for the fact that it will require an IPI to
        ///   flush remote PPs once SMP support is added to the guest.
        ///
        /// - On AMD, we can state that we only support Zen 3 and above
        ///   which means that we can use the remote TLB flush instructions
        ///   from AMD. On Intel, handling IPIs is not as bad because we
        ///   can repurpose INIT and trap on it. On AMD, this is not as
        ///   simple, and so the remote TLB flush instructions are the
        ///   way to handle this.
        ///
        /// - If we do need to handle this, keep in mind that this
        ///   function has to be operated on in reverse. That include
        ///   unpinning memory that is no longer needed by the guest VM.
        ///

        /// NOTE:
        /// - Whe modifying a memory slot, we need to make sure that the
        ///   slot size is not changed. Basically, we are allowed to
        ///   delete, change flags, etc... but you are not allowed to
        ///   change the size.
        ///

        bferror("modifying an existing slot is currently not implemeneted");
        return SHIM_FAILURE;
    }

    pmut_vm->slots[mut_slot_id] = *args;

    if (platform_mlock((void *)mut_src, args->memory_size)) {
        bferror("platform_mlock failed");
        goto platform_mlock_failed;
    }

    pmut_mut_mdl->num_entries = ((uint64_t)0);
    for (mut_i = ((int64_t)0); mut_i < mut_size; mut_i += (int64_t)HYPERVISOR_PAGE_SIZE) {
        uint64_t const dst = mut_dst + (uint64_t)mut_i;
        uint64_t const src = platform_virt_to_phys_user(mut_src + (uint64_t)mut_i);

        if (((uint64_t)0) == src) {
            bferror("platform_virt_to_phys_user failed");
            goto mv_vm_op_mmio_map_failed;
        }

        pmut_mut_mdl->entries[pmut_mut_mdl->num_entries].dst = dst;
        pmut_mut_mdl->entries[pmut_mut_mdl->num_entries].src = src;
        pmut_mut_mdl->entries[pmut_mut_mdl->num_entries].bytes = HYPERVISOR_PAGE_SIZE;
        ++pmut_mut_mdl->num_entries;

        /// TODO:
        /// - Need to add support for memory flags. Right now, MicroV ignores
        ///   the flags field and always sets the memory to RWE. This needs
        ///   to be fixed, and then we will need to translate the KVM flags
        ///   to MicroV flags here and send them up properly.
        ///

        /// TODO:
        /// - Right now MicroV assumes that every entry is 4k in size.
        ///   Instead, it should be modified to handle any page aligned
        ///   size. This code should then look to see if the previous
        ///   entry is contiguous with this one. If it is, all we need
        ///   to do is increment the previous entry's total bytes by a
        ///   page size. Contiguous memory is HIGHLY likely, and will
        ///   dramatically reduce how often this code has to hypercall
        ///   up to MicroV by "compressing" the entires.
        ///
        if (pmut_mut_mdl->num_entries >= MV_MDL_MAX_ENTRIES) {
            if (mv_vm_op_mmio_map(g_mut_hndl, pmut_vm->id, MV_SELF_ID)) {
                bferror("mv_vm_op_mmio_map failed");
                goto mv_vm_op_mmio_map_failed;
            }

            pmut_mut_mdl->num_entries = ((uint64_t)0);
        }
        else {
            mv_touch();
        }
    }

    if (((uint64_t)0) != pmut_mut_mdl->num_entries) {
        if (mv_vm_op_mmio_map(g_mut_hndl, pmut_vm->id, MV_SELF_ID)) {
            bferror("mv_vm_op_mmio_map failed");
            goto mv_vm_op_mmio_map_failed;
        }

        mv_touch();
    }
    else {
        mv_touch();
    }

    platform_mutex_unlock(&pmut_vm->mutex);
    return SHIM_SUCCESS;

mv_vm_op_mmio_map_failed:

    /// NOTE:
    /// - If an error occurs, we need to undo what we have already started.
    ///   For example, MicroV might run out of pages and throw an error. Or
    ///   userspace might attempt to provide overlapping slots, which is not
    ///   supported.
    ///
    /// - To undo what we stared above, we need to perform the operations
    ///   above in reverse. When we add SMP support, we need to be careful
    ///   here. Any modifications here that the guest on a remote PP can
    ///   pull into it's TLB need to also be reversed, so a TLB flush on
    ///   every single hypercall would be needed to ensure consistency. If
    ///   the other PP's are paused until this entire IOCTL is complete,
    ///   there would be no issue, but that is a really bad idea, as the MMIO
    ///   hypercalls are slow, and likely will require continuations in the
    ///   future, meaning pausing a guest's VPs is likely very expensive.
    ///
    /// - With any luck, this IOCTL is only used on startup, in which case
    ///   these issues are only really a problem if we ever attempt to
    ///   support migration.
    ///

    pmut_mut_mdl->num_entries = ((uint64_t)0);
    for (; mut_i >= ((int64_t)0); mut_i -= HYPERVISOR_PAGE_SIZE) {
        uint64_t const dst = mut_dst + (uint64_t)mut_i;
        uint64_t const src = platform_virt_to_phys((void *)(mut_src + (uint64_t)mut_i));

        pmut_mut_mdl->entries[pmut_mut_mdl->num_entries].dst = dst;
        pmut_mut_mdl->entries[pmut_mut_mdl->num_entries].src = src;
        pmut_mut_mdl->entries[pmut_mut_mdl->num_entries].bytes = HYPERVISOR_PAGE_SIZE;
        ++pmut_mut_mdl->num_entries;

        if (pmut_mut_mdl->num_entries >= MV_MDL_MAX_ENTRIES) {
            (void)mv_vm_op_mmio_unmap(g_mut_hndl, pmut_vm->id);

            pmut_mut_mdl->num_entries = ((uint64_t)0);
        }
        else {
            mv_touch();
        }
    }

    if (((uint64_t)0) != pmut_mut_mdl->num_entries) {
        (void)mv_vm_op_mmio_unmap(g_mut_hndl, pmut_vm->id);

        mv_touch();
    }
    else {
        mv_touch();
    }

    platform_expects(SHIM_SUCCESS == platform_munlock((void *)mut_src, args->memory_size));
platform_mlock_failed:

    platform_mutex_unlock(&pmut_vm->mutex);
    return SHIM_FAILURE;
}
