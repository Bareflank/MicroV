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

#ifndef MV_EXIT_REASON_T_H
#define MV_EXIT_REASON_T_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __cplusplus
    /**
     * <!-- description -->
     *   @brief Defines the exit reason for mv_vs_op_run
     */
    enum mv_exit_reason_t : int32_t
#else
/**
     * <!-- description -->
     *   @brief Defines the exit reason for mv_vs_op_run
     */
enum mv_exit_reason_t
#endif
    {
        /** @brief returned on error */
        mv_exit_reason_t_failure = 0,
        /** @brief an unknown/unsupported VMExit has occurred */
        mv_exit_reason_t_unknown = 1,
        /** @brief a halt event has occurred */
        mv_exit_reason_t_hlt = 2,
        /** @brief a IO event has occurred */
        mv_exit_reason_t_io = 3,
        /** @brief a MMIO event has occurred */
        mv_exit_reason_t_mmio = 4,
        /** @brief a MSR event has occurred */
        mv_exit_reason_t_msr = 5,
        /** @brief an interrupt event has occurred */
        mv_exit_reason_t_interrupt = 6,
        /** @brief an interrupt window event has occurred */
        mv_exit_reason_t_interrupt_window = 7,
        /** @brief an nmi event has occurred */
        mv_exit_reason_t_nmi = 8,
        /** @brief a shutdown event has occurred */
        mv_exit_reason_t_shutdown = 9,
    };

    /**
     * <!-- description -->
     *   @brief Returns (int32_t)val
     *
     * <!-- inputs/outputs -->
     *   @param val the mv_exit_reason_t to convert
     *   @return Returns (int32_t)val
     */
    NODISCARD CONSTEXPR int32_t
    mv_exit_reason_t_to_i32(enum mv_exit_reason_t const val) NOEXCEPT
    {
        return (int32_t)val;
    }

    /**
     * <!-- description -->
     *   @brief Returns (uint64_t)val
     *
     * <!-- inputs/outputs -->
     *   @param val the mv_exit_reason_t to convert
     *   @return Returns (uint64_t)val
     */
    NODISCARD CONSTEXPR uint64_t
    mv_exit_reason_t_to_u64(enum mv_exit_reason_t const val) NOEXCEPT
    {
        return (uint64_t)val;
    }

    /**
     * <!-- description -->
     *   @brief Returns (mv_exit_reason_t)val
     *
     * <!-- inputs/outputs -->
     *   @param val the mv_exit_reason_t to convert
     *   @return Returns (mv_exit_reason_t)val
     */
    NODISCARD CONSTEXPR enum mv_exit_reason_t
    i32_to_mv_exit_reason_t(int32_t const val) NOEXCEPT
    {
        return (enum mv_exit_reason_t)val;
    }

    /**
     * <!-- description -->
     *   @brief Returns (mv_exit_reason_t)val
     *
     * <!-- inputs/outputs -->
     *   @param val the mv_exit_reason_t to convert
     *   @return Returns (mv_exit_reason_t)val
     */
    NODISCARD CONSTEXPR enum mv_exit_reason_t
    u64_to_mv_exit_reason_t(uint64_t const val) NOEXCEPT
    {
        return (enum mv_exit_reason_t)val;
    }

/** @brief integer version of mv_exit_reason_t_failure */
#define EXIT_REASON_FAILURE ((int32_t)mv_exit_reason_t_failure)
/** @brief integer version of mv_exit_reason_t_unknown */
#define EXIT_REASON_UNKNOWN ((int32_t)mv_exit_reason_t_unknown)
/** @brief integer version of mv_exit_reason_t_hlt */
#define EXIT_REASON_HLT ((int32_t)mv_exit_reason_t_hlt)
/** @brief integer version of mv_exit_reason_t_io */
#define EXIT_REASON_IO ((int32_t)mv_exit_reason_t_io)
/** @brief integer version of mv_exit_reason_t_mmio */
#define EXIT_REASON_MMIO ((int32_t)mv_exit_reason_t_mmio)
/** @brief integer version of mv_exit_reason_t_msr */
#define EXIT_REASON_MSR ((int32_t)mv_exit_reason_t_msr)
/** @brief integer version of mv_exit_reason_t_interrupt */
#define EXIT_REASON_INTERRUPT ((int32_t)mv_exit_reason_t_interrupt)
/** @brief integer version of mv_exit_reason_t_nmi */
#define EXIT_REASON_NMI ((int32_t)mv_exit_reason_t_nmi)

#ifdef __cplusplus
}
#endif

#endif
