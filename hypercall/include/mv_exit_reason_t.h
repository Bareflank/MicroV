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
    };

#ifdef __cplusplus
}
#endif

#endif
