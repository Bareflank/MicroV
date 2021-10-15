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

#ifndef PLATFORM_H
#define PLATFORM_H

#include <mv_types.h>

#if defined(WINDOWS_KERNEL)
#include <wdm.h>
typedef FAST_MUTEX platform_mutex;
#elif defined(LINUX_KERNEL)
#include <linux/mutex.h>
typedef struct mutex platform_mutex;
#else
typedef uint64_t platform_mutex;
#endif

#ifdef __cplusplus
namespace shim
{
    extern "C"
    {
#endif

/** @brief execute each CPU in forward order (i.e., incrementing) */
#define PLATFORM_FORWARD ((uint32_t)0U)
/** @brief execute each CPU in reverse order (i.e., decrementing) */
#define PLATFORM_REVERSE ((uint32_t)1U)

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
        void platform_expects(int const test) NOEXCEPT;

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
        void platform_ensures(int const test) NOEXCEPT;

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
        NODISCARD void *platform_alloc(uint64_t const size) NOEXCEPT;

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
        void platform_free(void *const pmut_ptr, uint64_t const size) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Given a virtual address, this function returns the virtual
         *     address's physical address. Only works with memory allocated using
         *     platform_alloc. Returns ((void *)0) if the conversion failed.
         *
         * <!-- inputs/outputs -->
         *   @param virt the virtual address to convert to a physical address
         *   @return Given a virtual address, this function returns the virtual
         *     address's physical address. Only works with memory allocated using
         *     platform_alloc. Returns ((void *)0) if the conversion failed.
         */
        NODISCARD uintptr_t platform_virt_to_phys(void const *const virt) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Given a virtual address, this function returns the virtual
         *     address's physical address. Only works on memory owned by userspace.
         *     Returns ((void *)0) if the conversion failed.
         *
         * <!-- inputs/outputs -->
         *   @param virt the virtual address to convert to a physical address
         *   @return Given a virtual address, this function returns the virtual
         *     address's physical address. Only works on memory owned by userspace.
         *     Returns ((void *)0) if the conversion failed.
         */
        NODISCARD uintptr_t platform_virt_to_phys_user(uintptr_t const virt) NOEXCEPT;

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
        void platform_memset(void *const pmut_ptr, uint8_t const val, uint64_t const num) NOEXCEPT;

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
        platform_memcpy(void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Locks the pages within a memory region starting at
         *     "pmut_ptr" and continuing for "num" bytes. Once locked, the
         *     memory is guaranteed to never be paged out to disk.
         *
         * <!-- inputs/outputs -->
         *   @param pmut_ptr a pointer to the memory to lock
         *   @param num the number of bytes to lock.
         *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
         */
        NODISCARD int64_t platform_mlock(void *const pmut_ptr, uint64_t const num) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Unlocks the pages within a memory region starting at
         *     "pmut_ptr" and continuing for "num" bytes. Once unlocked, the
         *     memory is allowed to be paged out to disk.
         *
         * <!-- inputs/outputs -->
         *   @param pmut_ptr a pointer to the memory to unlock
         *   @param num the number of bytes to unlock.
         *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
         */
        NODISCARD int64_t platform_munlock(void *const pmut_ptr, uint64_t const num) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Copies "num" bytes from "src" to "pmut_dst". Returns
         *     SHIM_SUCCESS on success, SHIM_FAILURE on failure.
         *
         * <!-- inputs/outputs -->
         *   @param pmut_dst a pointer to the memory to copy to
         *   @param src a pointer to the memory to copy from
         *   @param num the number of bytes to copy
         *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
         */
        NODISCARD int64_t platform_copy_from_user(
            void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Copies "num" bytes from "src" to "pmut_dst". Returns
         *     SHIM_SUCCESS on success, SHIM_FAILURE on failure.
         *
         * <!-- inputs/outputs -->
         *   @param pmut_dst a pointer to the memory to copy to
         *   @param src a pointer to the memory to copy from
         *   @param num the number of bytes to copy
         *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
         */
        NODISCARD int64_t platform_copy_to_user(
            void *const pmut_dst, void const *const src, uint64_t const num) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Returns the total number of online CPUs (i.e. PPs)
         *
         * <!-- inputs/outputs -->
         *   @return Returns the total number of online CPUs (i.e. PPs)
         */
        NODISCARD uint32_t platform_num_online_cpus(void) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Returns the current CPU (i.e. PP)
         *
         * <!-- inputs/outputs -->
         *   @return Returns the current CPU (i.e. PP)
         */
        NODISCARD uint32_t platform_current_cpu(void) NOEXCEPT;

        /**
         * @brief The callback signature for platform_on_each_cpu
         */
        typedef int64_t (*platform_per_cpu_func)(uint32_t const) NOEXCEPT;

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
         *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
         */
        NODISCARD int64_t
        platform_on_each_cpu(platform_per_cpu_func const pmut_func, uint32_t const order) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Initializes a mutex lock. This must be called before a
         *     mutex can be used.
         *
         * <!-- inputs/outputs -->
         *   @param pmut_mutex the mutex to lock
         */
        void platform_mutex_init(platform_mutex *const pmut_mutex) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Destroys a mutex object. This must be called to free resources
         *     allocated from platform_mutex_init.
         *
         * <!-- inputs/outputs -->
         *   @param pmut_mutex the mutex to destroy
         */
        void platform_mutex_destroy(platform_mutex *const pmut_mutex) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Locks a mutex object. The mutex object must be initialized
         *     using platform_mutex_init before it is used.
         *
         * <!-- inputs/outputs -->
         *   @param pmut_mutex the mutex to lock
         */
        void platform_mutex_lock(platform_mutex *const pmut_mutex) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Unlocks a mutex object. The mutex object must be initialized
         *     using platform_mutex_init before it is used.
         *
         * <!-- inputs/outputs -->
         *   @param pmut_mutex the mutex to unlock
         */
        void platform_mutex_unlock(platform_mutex *const pmut_mutex) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Returns SHIM_INTERRUPTED if the current process has NOT
         *     been interrupted. Returns SHIM_FAILURE otherwise.
         *
         * <!-- inputs/outputs -->
         *   @return Returns SHIM_INTERRUPTED if the current process has NOT
         *     been interrupted. Returns SHIM_FAILURE otherwise.
         */
        NODISCARD int64_t platform_interrupted(void) NOEXCEPT;

        /**
         * <!-- description -->
         *   @brief Returns the TSC frequency of the PP this is called on
         *     in KHz.
         *
         * <!-- inputs/outputs -->
         *   @return Returns the TSC frequency of the PP this is called on
         *     in KHz.
         */
        NODISCARD uint64_t platform_tsc_khz(void) NOEXCEPT;

#ifdef __cplusplus
    }
}
#endif

#endif
