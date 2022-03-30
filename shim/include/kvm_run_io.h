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

#ifndef KVM_RUN_IO_H
#define KVM_RUN_IO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief n/a */
#define KVM_EXIT_IO_IN ((uint8_t)0x00)
/** @brief n/a */
#define KVM_EXIT_IO_OUT ((uint8_t)0x01)
/** @brief n/a */
#define KVM_EXIT_IO_MAX_DATA_SIZE ((uint8_t)0x270)

    /**
     * <!-- description -->
     *   @brief TODO
     */
    struct kvm_run_io
    {
        /** @brief TODO */
        uint8_t direction;
        /** @brief TODO */
        uint8_t size;
        /** @brief TODO */
        uint16_t port;
        /** @brief TODO */
        uint32_t count;
        /** @brief TODO */
        uint64_t data_offset;

        /**
         * <!-- description -->
         *   @brief TODO
         */
        // NOLINTNEXTLINE(bsl-decl-forbidden)
        union
        {
            /** @brief stores the data */
            uint8_t data[KVM_EXIT_IO_MAX_DATA_SIZE];
            /** @brief stores the data from the target register */
            uint64_t reg0;
        };
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif