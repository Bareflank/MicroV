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

#ifndef MV_MP_STATE_T_H
#define MV_MP_STATE_T_H

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __cplusplus
    /**
     * <!-- description -->
     *   @brief Defines different bit sizes for address, operands, etc.
     */
    enum mv_mp_state_t : int32_t
#else
/**
     * <!-- description -->
     *   @brief Defines the multiprocessor state of a VS
     */
enum mv_mp_state_t
#endif
    {
        /** @brief the initial state of the VS */
        mv_mp_state_t_initial = 0,
        /** @brief the VS is running */
        mv_mp_state_t_running = 1,
        /** @brief the VS is waiting for an interrupt */
        mv_mp_state_t_wait = 2,
        /** @brief the VS is waiting for INIT (x86 only) */
        mv_mp_state_t_init = 3,
        /** @brief the VS is waiting for SIPI (x86 only) */
        mv_mp_state_t_sipi = 4,
    };

/** @brief integer version of mv_mp_state_t_initial */
#define MP_STATE_INITIAL ((int32_t)mv_mp_state_t_initial)
/** @brief integer version of mv_mp_state_t_running */
#define MP_STATE_RUNNING ((int32_t)mv_mp_state_t_running)
/** @brief integer version of mv_mp_state_t_wait */
#define MP_STATE_WAIT ((int32_t)mv_mp_state_t_wait)
/** @brief integer version of mv_mp_state_t_init */
#define MP_STATE_INIT ((int32_t)mv_mp_state_t_init)
/** @brief integer version of mv_mp_state_t_sipi */
#define MP_STATE_SIPI ((int32_t)mv_mp_state_t_sipi)

#ifdef __cplusplus
}
#endif

#endif
