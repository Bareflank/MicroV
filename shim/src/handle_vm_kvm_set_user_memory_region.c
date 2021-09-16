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
#include <errno.h>
#include <g_mut_hndl.h>
#include <kvm_userspace_memory_region.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_mdl_t.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vm_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_set_user_memory_region.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_shim_vm the shim_vm_t argument
 *   @param args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vm_kvm_set_user_memory_region(
    struct shim_vm_t *const pmut_shim_vm, struct kvm_userspace_memory_region *const args) NOEXCEPT
{
    int64_t ret = 0ULL;
    uint64_t i = 0ULL;

    const uint16_t slot_id = (uint16_t)args->slot;
    int16_t *slot_idx = &pmut_shim_vm->slot_id_to_index[slot_id];
    struct kvm_slot_t *kslot;

    const uint16_t as_id = args->slot >> 16;
    const uint64_t addr = args->userspace_addr;
    const uint64_t gpa = args->guest_phys_addr;
    const uint64_t size = args->memory_size;
    const uint32_t kvm_flags = args->flags;
    uint64_t mv_flags =
        MV_MAP_FLAG_READ_ACCESS | MV_MAP_FLAG_WRITE_ACCESS | MV_MAP_FLAG_EXECUTE_ACCESS;

    struct mv_mdl_t *mdl = (struct mv_mdl_t *)shared_page_for_current_pp();
    mdl->num_entries = 0;

    platform_expects(!pmut_shim_vm);
    platform_expects(!args);

    if (size & 0x0000000000000FFFULL) {
        bferror("memory_size is not alligned\n");
        return SHIM_FAILURE;
    }
    if (gpa & 0x0000000000000FFFULL) {
        bferror("guest_phys_addr is not alligned\n");
        return SHIM_FAILURE;
    }
    if (addr & 0x0000000000000FFF) {
        bferror("userspace_addr is not alligned\n");
        return SHIM_FAILURE;
    }
    if (!addr) {
        bferror("userspace_addr cannot be 0\n");
        return SHIM_FAILURE;
    }
    if (args->slot >= KVM_USER_MEM_SLOTS) {
        bferror("slot is out of bound\n");
        return SHIM_FAILURE;
    }
    if (as_id >= KVM_ADDRESS_SPACE_NUM) {
        bferror("slot is out of bound\n");
        return SHIM_FAILURE;
    }

    platform_mutex_lock(&pmut_shim_vm->mutex);

    if (*slot_idx < 0) {
        // Create slot
        *slot_idx = pmut_shim_vm->used_slots++;
        kslot = &pmut_shim_vm->slots[*slot_idx];

        kslot->id = (int16_t)slot_id;
        kslot->as_id = as_id;
        kslot->base_gfn = gpa >> 12ULL;
        kslot->npages = (uint32_t)(size >> 12ULL);
        kslot->userspace_addr = addr;
        kslot->flags = kvm_flags;
    }
    else if (size == 0) {
        // Delete slot
        --pmut_shim_vm->used_slots;
        kslot = &pmut_shim_vm->slots[*slot_idx];
        *slot_idx = -1;
        // TODO sanitize args with existing slot or just use existing slot?
        i = kslot->npages * HYPERVISOR_PAGE_SIZE;
        goto undo_mmio_map;
    }
    else {
        // Update or move slot
        bferror("Updating or moving a slot is not yet implemented\n");
        goto unlock;
    }

    if ((ret = platform_mempin((void *)addr, size))) {
        goto unlock;
    }

    for (; i < size; i += HYPERVISOR_PAGE_SIZE) {
        mdl->entries[mdl->num_entries].dst = gpa + i;
        mdl->entries[mdl->num_entries].src = platform_virt_to_phys((void *)(addr + i));
        mdl->entries[mdl->num_entries].bytes = HYPERVISOR_PAGE_SIZE;
        mdl->entries[mdl->num_entries].flags = mv_flags;    // TODO: KVM to MicroV flags

        if (mdl->num_entries >= MV_MDL_MAX_ENTRIES) {
            if (mv_vm_op_mmio_map(g_mut_hndl, pmut_shim_vm->id, MV_SELF_ID) != MV_STATUS_SUCCESS) {
                bferror("error while mapping pages...");
                goto undo_mmio_map;
            }
            mdl->num_entries = 0;
        }
        else {
            ++mdl->num_entries;
        }
    }
    if (mdl->num_entries < MV_MDL_MAX_ENTRIES) {
        if (mv_vm_op_mmio_map(g_mut_hndl, pmut_shim_vm->id, MV_SELF_ID) != MV_STATUS_SUCCESS) {
            bferror("error while mapping pages..");
            goto undo_mmio_map;
        }
    }

    platform_mutex_unlock(&pmut_shim_vm->mutex);

    return SHIM_SUCCESS;

undo_mmio_map:
    mdl->num_entries = 0;
    for (; i > 0; i -= HYPERVISOR_PAGE_SIZE) {
        mdl->entries[mdl->num_entries].dst = gpa + i;
        mdl->entries[mdl->num_entries].src = platform_virt_to_phys((void *)(addr + i));
        mdl->entries[mdl->num_entries].bytes = HYPERVISOR_PAGE_SIZE;
        mdl->entries[mdl->num_entries].flags = mv_flags;    // TODO: original flags

        if (mdl->num_entries >= MV_MDL_MAX_ENTRIES) {
            if (mv_vm_op_mmio_unmap(g_mut_hndl, pmut_shim_vm->id) != MV_STATUS_SUCCESS) {
                bferror("error while unmapping pages...");
            }
            mdl->num_entries = 0;
        }
        else {
            ++mdl->num_entries;
        }
    }
    if (mdl->num_entries < MV_MDL_MAX_ENTRIES) {
        if (mv_vm_op_mmio_map(g_mut_hndl, pmut_shim_vm->id, MV_SELF_ID) != MV_STATUS_SUCCESS) {
            bferror("error while unmapping pages..");
        }
    }

    // platform_memunpin((void *)addr, size)

unlock:
    platform_mutex_unlock(&pmut_shim_vm->mutex);
    return ret;
}
