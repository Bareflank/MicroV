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
#include "mv_mdl_entry_t.h"
#include "mv_rdl_entry_t.h"

#include <debug.h>
#include <detect_hypervisor.h>
#include <g_mut_hndl.h>
#include <kvm_run.h>
#include <kvm_run_io.h>
#include <mv_bit_size_t.h>
#include <mv_exit_io_t.h>
#include <mv_exit_mmio_t.h>
#include <mv_exit_reason_t.h>
#include <mv_hypercall.h>
#include <mv_reg_t.h>
#include <mv_run_t.h>
#include <mv_types.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vcpu_t.h>

/**
 * <!-- description -->
 *   @brief Sets the exit reason to failure, and returns failure, telling
 *     userspace that something went wrong in the shim.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @return Returns SHIM_FAILURE
 */
NODISCARD static int64_t
return_failure(struct shim_vcpu_t *const pmut_vcpu) NOEXCEPT
{
    pmut_vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
    return SHIM_FAILURE;
}

/**
 * <!-- description -->
 *   @brief Returns an offset of a pointer WRT kvm_run
 *
 * <!-- inputs/outputs -->
 *   @param vcpu the VCPU associated with the IOCTL
 *   @param ptr the pointer to get the offset for
 *   @return Returns an offset of a pointer WRT kvm_run
 */
NODISCARD static uint64_t
get_offset(struct shim_vcpu_t const *const vcpu, void const *const ptr) NOEXCEPT
{
    return (uint64_t)((uint8_t const *)ptr - (uint8_t const *)vcpu->run);
}

/**
 * <!-- description -->
 *   @brief Handles mv_exit_reason_t_failure
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @return Returns SHIM_FAILURE
 */
NODISCARD static int64_t
handle_vcpu_kvm_run_failure(struct shim_vcpu_t *const pmut_vcpu) NOEXCEPT
{
    /// TODO:
    /// - We need to implement this the same way that KVM would. Right now
    ///   the MicroV ABI leaves this reserved, but if there is any info
    ///   that is needed to make this work, we either need to call MicroV
    ///   to get it, or, if it makes sense for MicroV to have this info
    ///   in the mv_exit_failure_t, we can add it. But only if it makes
    ///   sense, because in general, this is not in the hot path, and so
    ///   the shim can use other ABIs to get whatever info it needs on a
    ///   failure, which will simplify the ABI.
    ///

    pmut_vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
    return SHIM_FAILURE;
}

/**
 * <!-- description -->
 *   @brief Handles mv_exit_reason_t_unknown
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @return Returns SHIM_FAILURE
 */
NODISCARD static int64_t
handle_vcpu_kvm_run_unknown(struct shim_vcpu_t *const pmut_vcpu) NOEXCEPT
{
    /// TODO:
    /// - We need to implement this the same way that KVM would. Right now
    ///   the MicroV ABI leaves this reserved, but if there is any info
    ///   that is needed to make this work, we either need to call MicroV
    ///   to get it, or, if it makes sense for MicroV to have this info
    ///   in the mv_exit_failure_t, we can add it. But only if it makes
    ///   sense, because in general, this is not in the hot path, and so
    ///   the shim can use other ABIs to get whatever info it needs on a
    ///   failure, which will simplify the ABI.
    ///

    bfdebug_log("KVM_EXIT_UNKNOWN\n");
    pmut_vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
    return SHIM_FAILURE;
}


NODISCARD static int64_t
handle_vcpu_kvm_run_mmio(
    struct shim_vcpu_t *const pmut_vcpu, struct mv_exit_mmio_t *const pmut_exit_mmio) NOEXCEPT
{
    platform_expects(NULL != pmut_exit_mmio);

    // bfdebug_log("KVM_EXIT_MMIO:\n");
    // bfdebug_log("  gpa=0x%llx", (unsigned long long)pmut_exit_mmio->gpa);
    // bfdebug_log("  nrip=0x%llx", (unsigned long long)pmut_exit_mmio->nrip);
    // bfdebug_log("  target_reg=0x%llx", (unsigned long long)pmut_exit_mmio->target_reg);
    pmut_vcpu->run->mmio.phys_addr = pmut_exit_mmio->gpa;
    pmut_vcpu->run->mmio.nrip = pmut_exit_mmio->nrip;
    pmut_vcpu->run->mmio.target_reg = pmut_exit_mmio->target_reg;

    if(pmut_exit_mmio->flags == MV_EXIT_MMIO_READ) {
        // bfdebug_log("  READ\n");
        pmut_vcpu->run->mmio.is_write = 0;
    } else if(pmut_exit_mmio->flags == MV_EXIT_MMIO_WRITE) {
        // bfdebug_log("  WRITE\n");
        pmut_vcpu->run->mmio.is_write = 1;
    } else {
        bfdebug_log("  UNKNOWN FLAGS 0x%llx\n", (unsigned long long)pmut_exit_mmio->flags);
        return SHIM_FAILURE;
    }

    // bfdebug_log("  memory_access_size: 0x%llx\n", (unsigned long long)pmut_exit_mmio->memory_access_size);
    pmut_vcpu->run->mmio.len = (int32_t)pmut_exit_mmio->memory_access_size;
    // bfdebug_log("  data: 0x%llx\n", (unsigned long long)pmut_exit_mmio->data);
    *((uint64_t*)(&(pmut_vcpu->run->mmio.data))) = (int64_t)pmut_exit_mmio->data;

    // Indicate that we need to do a pre-run op
    pmut_vcpu->run->mmio.need_pre_op_run = 1;

    pmut_vcpu->run->exit_reason = KVM_EXIT_MMIO;
    return SHIM_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Handles mv_exit_reason_t_io
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @param pmut_exit_io pointer of type struct mv_exit_io_t to use
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD static int64_t
handle_vcpu_kvm_run_io(
    struct shim_vcpu_t *const pmut_vcpu, struct mv_exit_io_t *const pmut_exit_io) NOEXCEPT
{
    platform_expects(NULL != pmut_exit_io);

    switch (pmut_exit_io->type) {
        case MV_EXIT_IO_IN: {
            pmut_vcpu->run->io.direction = KVM_EXIT_IO_IN;
            break;
        }

        case MV_EXIT_IO_OUT: {
            pmut_vcpu->run->io.direction = KVM_EXIT_IO_OUT;
            break;
        }

        default: {
            bferror_x64("type is invalid/unsupported", pmut_exit_io->type);
            return return_failure(pmut_vcpu);
        }
    }

    pmut_vcpu->run->io.reg0 = *io_to_u64(pmut_exit_io->data);
    pmut_vcpu->run->io.data_offset = get_offset(pmut_vcpu, &pmut_vcpu->run->io.reg0);

    switch ((int32_t)pmut_exit_io->size) {
        case mv_bit_size_t_8: {
            pmut_vcpu->run->io.size = ((uint8_t)1);
            break;
        }

        case mv_bit_size_t_16: {
            pmut_vcpu->run->io.size = ((uint8_t)2);
            break;
        }

        case mv_bit_size_t_32: {
            pmut_vcpu->run->io.size = ((uint8_t)4);
            break;
        }

        case mv_bit_size_t_64:
        default: {
            bferror_d32("size is invalid", (uint32_t)pmut_exit_io->size);
            return return_failure(pmut_vcpu);
        }
    }

    if (pmut_exit_io->addr < INT16_MAX) {
        pmut_vcpu->run->io.port = (uint16_t)pmut_exit_io->addr;
    }
    else {
        bferror_d32("addr is invalid", (uint32_t)pmut_exit_io->size);
        return return_failure(pmut_vcpu);
    }

    if (pmut_exit_io->reps < INT32_MAX) {
        pmut_vcpu->run->io.count = (uint32_t)pmut_exit_io->reps;
    }
    else {
        bferror_x64("reps is invalid", pmut_exit_io->reps);
        return return_failure(pmut_vcpu);
    }

    pmut_vcpu->run->exit_reason = KVM_EXIT_IO;
    return SHIM_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Prepares the guest on IO intercepts before a run operation.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @param pmut_mv_run pointer of type struct mv_run_t to use
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
pre_run_op_io(struct shim_vcpu_t *const pmut_vcpu, struct mv_run_t *const pmut_mv_run) NOEXCEPT
{
    platform_expects(NULL != pmut_vcpu);
    platform_expects(NULL != pmut_vcpu->run);
    platform_expects(KVM_EXIT_IO == pmut_vcpu->run->exit_reason);
    platform_expects(NULL != pmut_mv_run);

    if (KVM_EXIT_IO_IN != (int)pmut_vcpu->run->io.direction) {
        return SHIM_SUCCESS;
    }
    mv_touch();

    if (1U == pmut_vcpu->run->io.count) {
        pmut_mv_run->num_reg_entries = (uint64_t)1U;
        pmut_mv_run->reg_entries[0].reg = (uint64_t)mv_reg_t_rax;
        pmut_mv_run->reg_entries[0].val = pmut_vcpu->run->io.reg0;
    }
    else if ((uint32_t)MV_RUN_MAX_MEM_REGION_SIZE < pmut_vcpu->run->io.count) {
        bferror_d32("FIXME: PIO size too big.", pmut_vcpu->run->io.count);
        // TODO: Implement run_op continuation
        return SHIM_FAILURE;
    }
    else {
        uint64_t const sz = (uint64_t)pmut_vcpu->run->io.count * (uint64_t)pmut_vcpu->run->io.size;
        uint64_t const dst = (uint64_t)0x42U;

        pmut_mv_run->mdl_entry.bytes = sz;
        pmut_mv_run->mdl_entry.dst = dst;    // FIXME

        platform_memcpy(pmut_mv_run->mem, pmut_vcpu->run->io.data, sz);

        pmut_mv_run->num_reg_entries = (uint64_t)0U;
        bferror_d32("FIXME: PIO address destination.", pmut_vcpu->run->io.count);
        return SHIM_FAILURE;
    }

    switch ((int)pmut_vcpu->run->io.size) {
        case 1: {
            break;
        }
        case 2: {
            break;
        }
        case 4: {
            break;
        }
        default: {
            bferror_x8("invalid io size", pmut_vcpu->run->io.size);
            return SHIM_FAILURE;
        }
    }

    // //FIXME: Put this in so that we don't try to do the MMIO pre-run again
    // pmut_vcpu->run->exit_reason = KVM_EXIT_INTR;

    return SHIM_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Prepares the guest on MMIO intercepts before a run operation.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @param pmut_mv_run pointer of type struct mv_run_t to use
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
pre_run_op_mmio(struct shim_vcpu_t *const pmut_vcpu, struct mv_run_t *const pmut_mv_run) NOEXCEPT
{
    platform_expects(NULL != pmut_vcpu);
    platform_expects(NULL != pmut_vcpu->run);
    platform_expects(KVM_EXIT_MMIO == pmut_vcpu->run->exit_reason);
    platform_expects(NULL != pmut_mv_run);

    if(!pmut_vcpu->run->mmio.need_pre_op_run) {
        // bfmmiodebug_log("pre_run_op_mmio: nothing to do!\n");
        // Nothing to do, we already did it
        return SHIM_SUCCESS;
    }

    // bfdebug_log("pre_run_op_mmio\n");

    // bfdebug_log("  nrip=0x%llx", (unsigned long long)pmut_vcpu->run->mmio.nrip);

    mv_touch();

    // Both reads & writes need to advance the instruction pointer
    pmut_mv_run->num_reg_entries = (uint64_t)1U;
    pmut_mv_run->reg_entries[0].reg = (uint64_t)mv_reg_t_rip;
    pmut_mv_run->reg_entries[0].val = pmut_vcpu->run->mmio.nrip;
    // bfdebug_log("  AFTER setting RIP = 0x%llx\n", (unsigned long long)pmut_vcpu->run->mmio.nrip);

    if (pmut_vcpu->run->mmio.is_write) {
        // For write operations, there is nothing else to do, just return
        pmut_vcpu->run->mmio.need_pre_op_run = 0;
        // bfdebug_log("  AFTER data: 0x%llx\n", *((unsigned long long *)pmut_vcpu->run->mmio.data));
        return SHIM_SUCCESS;
    }

    // bfdebug_log("  READ\n");
    // bfdebug_log("  target_reg=0x%llx", (unsigned long long)pmut_vcpu->run->mmio.target_reg);
    // bfdebug_log("  AFTER memory_access_size: 0x%llx\n", (unsigned long long)pmut_vcpu->run->mmio.len);
    // bfdebug_log("  AFTER data: 0x%llx\n", *((unsigned long long *)pmut_vcpu->run->mmio.data));

    if ((uint32_t)KVM_RUN_MMIO_DATA_SIZE < pmut_vcpu->run->mmio.len) {
        bferror_d32("FIXME: MMIO size too big.", pmut_vcpu->run->mmio.len);
        // TODO: Implement run_op continuation
        return SHIM_FAILURE;
    } else {
        // FIXME: do we need to know if it is a memory destination vs a register???
        pmut_mv_run->reg_entries[pmut_mv_run->num_reg_entries].reg = (uint64_t)pmut_vcpu->run->mmio.target_reg;
        pmut_mv_run->reg_entries[pmut_mv_run->num_reg_entries].val = *((uint64_t*)pmut_vcpu->run->mmio.data);
        pmut_mv_run->num_reg_entries++;

        // bfdebug_log("assume it was a read into eax, val=0x%llx\n", (unsigned long long)(pmut_mv_run->reg_entries[0].val));
    }

    switch ((int)pmut_vcpu->run->mmio.len) {
        case 1: {
            break;
        }
        case 2: {
            break;
        }
        case 4: {
            break;
        }
        case 8: {
            break;
        }
        default: {
            bfdebug_log("invalid mmio size 0x%llx\n", (unsigned long long)pmut_vcpu->run->mmio.len);
            return SHIM_FAILURE;
        }
    }

    //FIXME: Put this in so that we don't try to do the MMIO pre-run again
    pmut_vcpu->run->mmio.need_pre_op_run = 0;

    return SHIM_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Prepares the guest before a run operation.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @param pmut_mv_run pointer of type struct mv_run_t to use
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
pre_run_op(struct shim_vcpu_t *const pmut_vcpu, struct mv_run_t *const pmut_mv_run) NOEXCEPT
{
    platform_expects(NULL != pmut_vcpu);
    platform_expects(NULL != pmut_vcpu->run);
    platform_expects(NULL != pmut_mv_run);

    switch (pmut_vcpu->run->exit_reason) {
        case KVM_EXIT_IO: {
            pmut_mv_run->num_reg_entries = (uint64_t)0U;
            pmut_mv_run->num_msr_entries = (uint64_t)0U;

            return pre_run_op_io(pmut_vcpu, pmut_mv_run);
        }

        case KVM_EXIT_MMIO: {
            pmut_mv_run->num_reg_entries = (uint64_t)0U;
            pmut_mv_run->num_msr_entries = (uint64_t)0U;

            return pre_run_op_mmio(pmut_vcpu, pmut_mv_run);
        }

        case KVM_EXIT_INTR: {
            // FIXME: do we need this here???
            pmut_mv_run->num_reg_entries = (uint64_t)0U;
            pmut_mv_run->num_msr_entries = (uint64_t)0U;

            return SHIM_SUCCESS;
        }

        default: {
            // Nothing to do for this case
            break;
        }
    }

    // bferror_x64("pre_run_op: unhandled exit reason", (uint64_t)pmut_vcpu->run->exit_reason);

    return SHIM_SUCCESS;
}

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_run.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_run(struct shim_vcpu_t *const pmut_vcpu) NOEXCEPT
{
    int64_t mut_ret;
    enum mv_exit_reason_t mut_exit_reason;
    void *pmut_mut_exit;

    platform_expects(NULL != pmut_vcpu);
    platform_expects(NULL != pmut_vcpu->run);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return return_failure(pmut_vcpu);
    }

    pmut_mut_exit = shared_page_for_current_pp();


        mut_ret = pre_run_op(pmut_vcpu, (struct mv_run_t *)pmut_mut_exit);
        if (SHIM_FAILURE == mut_ret) {
            bferror("pre_run_op failed");
            goto release_shared_page;
        }

        mut_exit_reason = mv_vs_op_run(g_mut_hndl, pmut_vcpu->vsid);
        // bfdebug_log("[BAREFLANK DEBUG] mv_vs_op_run returned: 0x%x\n", mut_exit_reason);
        switch ((int32_t)mut_exit_reason) {
            case mv_exit_reason_t_failure: {
                mut_ret = handle_vcpu_kvm_run_failure(pmut_vcpu);
                goto release_shared_page;
            }

            case mv_exit_reason_t_unknown: {
                bfdebug_log("[BAREFLANK DEBUG] mv_vs_op_run returned: mv_exit_reason_t_unknown\n");
                mut_ret = handle_vcpu_kvm_run_unknown(pmut_vcpu);
                goto release_shared_page;
            }

            case mv_exit_reason_t_hlt: {
                bfdebug("run: mv_exit_reason_t_hlt exit");
                pmut_vcpu->run->exit_reason = KVM_EXIT_HLT;
                mut_ret = SHIM_SUCCESS;
                goto release_shared_page;
            }

            case mv_exit_reason_t_io: {
                mut_ret = handle_vcpu_kvm_run_io(pmut_vcpu, pmut_mut_exit);
                goto release_shared_page;
            }

            case mv_exit_reason_t_mmio: {
                mut_ret = handle_vcpu_kvm_run_mmio(pmut_vcpu, pmut_mut_exit);
                goto release_shared_page;
            }

            case mv_exit_reason_t_msr: {
                bferror("run: mv_exit_reason_t_msr exit");
                mut_ret = return_failure(pmut_vcpu);
                goto release_shared_page;
            }

            case mv_exit_reason_t_interrupt: {
                // bferror("run: mv_exit_reason_t_interrupt");
                release_shared_page_for_current_pp();
                if (platform_interrupted()) {
                    // bferror("platform_interrupted\n");
                    // pmut_vcpu->run->exit_reason = KVM_EXIT_INTR;
                    mut_ret = SHIM_INTERRUPTED;
                    goto ret;
                }
                if((pmut_vcpu->run->exit_reason == KVM_EXIT_MMIO) ||
                   (pmut_vcpu->run->exit_reason == KVM_EXIT_IO)) {
                    //FIXME: Put this in so that we don't try to do the MMIO pre-run again
                    pmut_vcpu->run->exit_reason = KVM_EXIT_INTR;
                }
                pmut_mut_exit = shared_page_for_current_pp();
                pmut_vcpu->run->exit_reason = KVM_EXIT_INTR;
                mut_ret = SHIM_INTERRUPTED;
                break;
            }

            case mv_exit_reason_t_interrupt_window: {
                bferror("run: interrupt window exit");
                platform_expects(!!pmut_vcpu->run->request_interrupt_window);
                // pmut_vcpu->run->if_flag = (uint8_t)1;
                pmut_vcpu->run->ready_for_interrupt_injection = (uint8_t)1;
                pmut_vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
                return SHIM_SUCCESS;
            }

            // case mv_exit_reason_t_nmi: {
            //     continue;
            // }

            case mv_exit_reason_t_shutdown: {
                pmut_vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
                mut_ret = SHIM_SUCCESS;
                goto release_shared_page;
            }

            default: {
                bferror_x64("unhandled exit reason: ", mut_exit_reason);
                bferror("mv_vs_op_run returned with an unsupported exit reason\n");
                mut_ret = return_failure(pmut_vcpu);
                goto release_shared_page;
            }
        }


release_shared_page:
    release_shared_page_for_current_pp();

ret:
    return mut_ret;
}
