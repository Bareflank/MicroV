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

#ifndef MV_EXIT_IO_T_HPP
#define MV_EXIT_IO_T_HPP

#include <mv_bit_size_t.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief The mv_exit_io_t defines an input access */
#define MV_EXIT_IO_IN ((uint64_t)0x0000000000000000)
/** @brief The mv_exit_io_t defines an output access */
#define MV_EXIT_IO_OUT ((uint64_t)0x0000000000000001)
/** @brief The mv_exit_io_t defines the max data capacity */
#define MV_EXIT_IO_MAX_DATA ((uint64_t)0x0000000000000FE4)

    /**
     * <!-- description -->
     *   @brief See mv_vs_op_run for more details
     */
    struct mv_exit_io_t
    {
        /** @brief stores the address of the IO register */
        uint64_t addr;
        /** @brief stores the number of repetitions to make */
        uint64_t reps;
        /** @brief stores MV_EXIT_IO flags */
        uint64_t type;
        /** @brief stores defines the bit size of the dst */
        enum mv_bit_size_t size;
        /** @brief stores the data to read/write */
        uint8_t data[MV_EXIT_IO_MAX_DATA];
    };

    /** <!-- description -->
     *    @brief Returns bsl::to_u64(reinterpret_cast<bsl::uintmx>(ptr))
     *
     *  <!-- inputs/outputs -->
     *    @param pmut_mut_arr the pointer to convert to a bsl::safe_u64
     *    @return Returns bsl::to_u64(reinterpret_cast<bsl::uintmx>(ptr))
     */
    NODISCARD CONSTEXPR uint64_t *
    io_to_u64(uint8_t pmut_mut_arr[]) NOEXCEPT
    {
        return (uint64_t *)&pmut_mut_arr[0];
    }

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
