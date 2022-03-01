/* SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT */

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

#ifndef TYPES_H
#define TYPES_H

#include <inttypes.h>       // IWYU pragma: export
#include <linux/errno.h>    // IWYU pragma: export
#include <stddef.h>         // IWYU pragma: export
#include <stdint.h>         // IWYU pragma: export

/**
 * @brief Returned by a shim function when a function succeeds.
 */
#define SHIM_SUCCESS ((int64_t)0)

/**
 * @brief Returned by a shim function when an error occurs.
 */
#define SHIM_FAILURE ((int64_t)-EINVAL)

/**
 * @brief Returned by a shim function when an the current process
 *   has been interrupted.
 */
#define SHIM_INTERRUPTED ((int64_t)-EINTR)

/**
 * @brief Returned by a shim function when a provided data structure
 *   is not large enough to hold the return data.
 */
#define SHIM_2BIG ((int64_t)-E2BIG)

/**
 * @brief Returned by a shim function when VCPU already exist.
 */
#define SHIM_EXIST ((int64_t)-EEXIST)
#endif
