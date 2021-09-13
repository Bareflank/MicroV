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

#include <assert.h>
#include <platform.h>
#include <stdlib.h>
#include <string.h>
#include <types.h>

/** @brief if non zero, platform_alloc fails after count hits zero */
int32_t g_mut_platform_alloc_fails = 0;
/** @brief number of online cpus */
uint32_t g_mut_platform_num_online_cpus = 1U;

/**
 * <!-- description -->
 *   @brief If test is false, a contract violation has occurred. This
 *     should be used to assert preconditions that if not meet, would
 *     result in undefined behavior. These should not be tested by a
 *     unit test, meaning they are contract violations. These asserts
 *     are simply there as a sanity check during a debug build.
 *
 * <!-- inputs/outputs -->
 *   @param test the contract to check
 */
void
platform_expects(int const test) NOEXCEPT
{
    assert(test);    // NOLINT // GRCOV_EXCLUDE_BR
}

/**
 * <!-- description -->
 *   @brief If test is false, a contract violation has occurred. This
 *     should be used to assert postconditions that if not meet, would
 *     result in undefined behavior. These should not be tested by a
 *     unit test, meaning they are contract violations. These asserts
 *     are simply there as a sanity check during a debug build.
 *
 * <!-- inputs/outputs -->
 *   @param test the contract to check
 */
void
platform_ensures(int const test) NOEXCEPT
{
    assert(test);    // NOLINT // GRCOV_EXCLUDE_BR
}

/**
 * <!-- description -->
 *   @brief This function allocates read/write virtual memory from the
 *     kernel. This memory is not physically contiguous. The resulting
 *     pointer is at least 4k aligned, so use this function sparingly
 *     as it will always allocate at least one page. Use platform_free()
 *     to release this memory.
 *
 *   @note This function must zero the allocated memory
 *
 * <!-- inputs/outputs -->
 *   @param size the number of bytes to allocate
 *   @return Returns a pointer to the newly allocated memory on success.
 *     Returns a nullptr on failure.
 */
NODISCARD void *
platform_alloc(uint64_t const size) NOEXCEPT
{
    void *pmut_mut_ret;
    platform_expects(((uint64_t)0) != size);

    if (g_mut_platform_alloc_fails > 0) {
        --g_mut_platform_alloc_fails;
        if (0 == g_mut_platform_alloc_fails) {
            return ((void *)0);
        }
    }

    pmut_mut_ret = malloc(size);
    platform_expects(((void *)0) != pmut_mut_ret);

    return memset(pmut_mut_ret, 0, size);    // NOLINT
}

/**
 * <!-- description -->
 *   @brief This function frees memory previously allocated using the
 *     platform_alloc() function.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ptr the pointer returned by platform_alloc(). If ptr is
 *     passed a nullptr, it will be ignored. Attempting to free memory
 *     more than once results in UB.
 *   @param size the number of bytes that were allocated. Note that this
 *     may or may not be ignored depending on the platform.
 */
void
platform_free(void *const pmut_ptr, uint64_t const size) NOEXCEPT
{
    (void)size;

    if (((void *)0) != pmut_ptr) {
        free(pmut_ptr);
    }
}

/**
 * <!-- description -->
 *   @brief Given a virtual address, this function returns the virtual
 *     address's physical address. Returns ((void *)0) if the conversion failed.
 *
 * <!-- inputs/outputs -->
 *   @param virt the virtual address to convert to a physical address
 *   @return Given a virtual address, this function returns the virtual
 *     address's physical address. Returns ((void *)0) if the conversion failed.
 */
NODISCARD uintptr_t
platform_virt_to_phys(void const *const virt) NOEXCEPT
{
    return (uintptr_t)virt;
}

/**
 * <!-- description -->
 *   @brief Sets "num" bytes in the memory pointed to by "ptr" to "val".
 *     If the provided parameters are valid, returns 0, otherwise
 *     returns SHIM_FAILURE.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_ptr a pointer to the memory to set
 *   @param val the value to set each byte to
 *   @param num the number of bytes in "pmut_ptr" to set to "val".
 */
void
platform_memset(void *const pmut_ptr, uint8_t const val, uint64_t const num) NOEXCEPT
{
    platform_expects(NULL != pmut_ptr);
    memset(pmut_ptr, (int32_t)val, num);    // NOLINT
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "pmut_dst". If "src" or "pmut_dst" are
 *     ((void *)0), returns SHIM_FAILURE, otherwise returns 0.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 */
void
platform_memcpy(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULL != pmut_dst);
    platform_expects(NULL != src);

    memcpy(pmut_dst, src, num);    // NOLINT
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "pmut_dst". If "src" or "pmut_dst" are
 *     ((void *)0), returns FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory from userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 */
void
platform_copy_from_user(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULL != pmut_dst);
    platform_expects(NULL != src);

    memcpy(pmut_dst, src, num);    // NOLINT
}

/**
 * <!-- description -->
 *   @brief Copies "num" bytes from "src" to "pmut_dst". If "src" or "pmut_dst" are
 *     ((void *)0), returns FAILURE, otherwise returns 0. Note that this function can
 *     be used to copy memory to userspace via an IOCTL.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_dst a pointer to the memory to copy to
 *   @param src a pointer to the memory to copy from
 *   @param num the number of bytes to copy
 */
void
platform_copy_to_user(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT
{
    platform_expects(NULL != pmut_dst);
    platform_expects(NULL != src);

    memcpy(pmut_dst, src, num);    // NOLINT
}

/**
 * <!-- description -->
 *   @brief Returns the total number of online CPUs (i.e. PPs)
 *
 * <!-- inputs/outputs -->
 *   @return Returns the total number of online CPUs (i.e. PPs)
 */
NODISCARD uint32_t
platform_num_online_cpus(void) NOEXCEPT
{
    return g_mut_platform_num_online_cpus;
}

/**
 * <!-- description -->
 *   @brief Returns the current CPU (i.e. PP)
 *
 * <!-- inputs/outputs -->
 *   @return Returns the current CPU (i.e. PP)
 */
NODISCARD uint32_t
platform_current_cpu(void) NOEXCEPT
{
    return 0U;
}

/**
 * <!-- description -->
 *   @brief Calls the user provided callback on each CPU. If each callback
 *     returns 0, this function returns 0, otherwise this function returns
 *     a non-0 value, even if all callbacks succeed except for one. If an
 *     error occurs, it is possible that this function will continue to
 *     execute the remaining callbacks until all callbacks have been called
 *     (depends on the platform).
 *
 * <!-- inputs/outputs -->
 *   @param pmut_func the function to call on each cpu
 *   @param order sets the order the CPUs are called
 *   @return If each callback returns 0, this function returns 0, otherwise
 *     this function returns a non-0 value
 */
NODISCARD int64_t
platform_on_each_cpu(platform_per_cpu_func const pmut_func, uint32_t const order) NOEXCEPT
{
    (void)order;
    return pmut_func(0U);
}

/**
 * <!-- description -->
 *   @brief Initializes a mutex lock. This must be called before a
 *     mutex can be used.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_mutex the mutex to lock
 */
void
// NOLINTNEXTLINE(readability-non-const-parameter)
platform_mutex_init(platform_mutex *const pmut_mutex) NOEXCEPT
{
    (void)pmut_mutex;
}

/**
 * <!-- description -->
 *   @brief Locks a mutex object. The mutex object must be initialized
 *     using platform_mutex_init before it is used.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_mutex the mutex to lock
 */
void
// NOLINTNEXTLINE(readability-non-const-parameter)
platform_mutex_lock(platform_mutex *const pmut_mutex) NOEXCEPT
{
    (void)pmut_mutex;
}

/**
 * <!-- description -->
 *   @brief Unlocks a mutex object. The mutex object must be initialized
 *     using platform_mutex_init before it is used.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_mutex the mutex to unlock
 */
void
// NOLINTNEXTLINE(readability-non-const-parameter)
platform_mutex_unlock(platform_mutex *const pmut_mutex) NOEXCEPT
{
    (void)pmut_mutex;
}
