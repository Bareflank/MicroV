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
#include <kvm_run.h>
#include <kvm_run_io.h>
#include <mv_bit_size_t.h>
#include <mv_exit_io_t.h>
#include <mv_exit_reason_t.h>
#include <mv_hypercall.h>
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

    pmut_vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
    return SHIM_FAILURE;
}

/**
 * <!-- description -->
 *   @brief Handles mv_exit_reason_t_io
 *
 * <!-- inputs/outputs -->
 *   @param pmut_vcpu the VCPU associated with the IOCTL
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD static int64_t
handle_vcpu_kvm_run_io(struct shim_vcpu_t *const pmut_vcpu) NOEXCEPT
{
    int64_t mut_ret = SHIM_FAILURE;

    struct mv_exit_io_t *const pmut_exit_io = (struct mv_exit_io_t *)shared_page_for_current_pp();
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
            mut_ret = return_failure(pmut_vcpu);
            goto release_shared_page;
        }
    }

    switch ((int32_t)pmut_exit_io->size) {
        case mv_bit_size_t_8: {
            pmut_vcpu->run->io.size = ((uint8_t)1);
            pmut_vcpu->run->io.data8 = (uint8_t)pmut_exit_io->data;
            pmut_vcpu->run->io.data_offset = get_offset(pmut_vcpu, &pmut_vcpu->run->io.data8);
            break;
        }

        case mv_bit_size_t_16: {
            pmut_vcpu->run->io.size = ((uint8_t)2);
            pmut_vcpu->run->io.data16 = (uint16_t)pmut_exit_io->data;
            pmut_vcpu->run->io.data_offset = get_offset(pmut_vcpu, &pmut_vcpu->run->io.data16);
            break;
        }

        case mv_bit_size_t_32: {
            pmut_vcpu->run->io.size = ((uint8_t)4);
            pmut_vcpu->run->io.data32 = (uint32_t)pmut_exit_io->data;
            pmut_vcpu->run->io.data_offset = get_offset(pmut_vcpu, &pmut_vcpu->run->io.data32);
            break;
        }

        case mv_bit_size_t_64:
        default: {
            bferror_d32("size is invalid", (uint32_t)pmut_exit_io->size);
            mut_ret = return_failure(pmut_vcpu);
            goto release_shared_page;
        }
    }

    if (pmut_exit_io->addr < INT16_MAX) {
        pmut_vcpu->run->io.port = (uint16_t)pmut_exit_io->addr;
    }
    else {
        bferror_d32("addr is invalid", (uint32_t)pmut_exit_io->size);
        mut_ret = return_failure(pmut_vcpu);
        goto release_shared_page;
    }

    if (pmut_exit_io->reps < INT32_MAX) {
        pmut_vcpu->run->io.count = (uint32_t)pmut_exit_io->reps;
    }
    else {
        bferror_x64("reps is invalid", pmut_exit_io->reps);
        mut_ret = return_failure(pmut_vcpu);
        goto release_shared_page;
    }

    pmut_vcpu->run->exit_reason = KVM_EXIT_IO;
    mut_ret = SHIM_SUCCESS;

release_shared_page:
    release_shared_page_for_current_pp();

    return mut_ret;
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
    enum mv_exit_reason_t mut_exit_reason;
    platform_expects(NULL != pmut_vcpu);
    platform_expects(NULL != pmut_vcpu->run);

    if (detect_hypervisor()) {
        bferror("The shim is not running in a VM. Did you forget to start MicroV?");
        return return_failure(pmut_vcpu);
    }

    while (0 == (int32_t)pmut_vcpu->run->immediate_exit) {
        if (platform_interrupted()) {
            break;
        }

        mut_exit_reason = mv_vs_op_run(g_mut_hndl, pmut_vcpu->vsid);
        switch ((int32_t)mut_exit_reason) {
            case mv_exit_reason_t_failure: {
                return handle_vcpu_kvm_run_failure(pmut_vcpu);
            }

            case mv_exit_reason_t_unknown: {
                return handle_vcpu_kvm_run_unknown(pmut_vcpu);
            }

            case mv_exit_reason_t_hlt: {
                bferror("mv_exit_reason_t_hlt currently not implemented\n");
                return return_failure(pmut_vcpu);
            }

            case mv_exit_reason_t_io: {
                return handle_vcpu_kvm_run_io(pmut_vcpu);
            }

            case mv_exit_reason_t_mmio: {
                bferror("mv_exit_reason_t_mmio currently not implemented\n");
                return return_failure(pmut_vcpu);
            }

            case mv_exit_reason_t_msr: {
                bferror("mv_exit_reason_t_msr currently not implemented\n");
                return return_failure(pmut_vcpu);
            }

            case mv_exit_reason_t_interrupt: {
                continue;
            }

            case mv_exit_reason_t_interrupt_window: {
                bferror("run: interrupt window exit");
                platform_expects(pmut_vcpu->run->request_interrupt_window);
                // pmut_vcpu->run->if_flag = (uint8_t)1;
                pmut_vcpu->run->ready_for_interrupt_injection = (uint8_t)1;
                pmut_vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
                return SHIM_SUCCESS;
            }

            case mv_exit_reason_t_nmi: {
                continue;
            }

            case mv_exit_reason_t_shutdown: {
                bferror("run: shutdown exit");
                pmut_vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
                return SHIM_SUCCESS;
            }

            default: {
                bferror_x64("unhandled exit reason: ", mut_exit_reason);
                break;
            }
        }

        bferror("mv_vs_op_run returned with an unsupported exit reason\n");
        return return_failure(pmut_vcpu);
    }

    pmut_vcpu->run->exit_reason = KVM_EXIT_INTR;
    return SHIM_INTERRUPTED;
}
