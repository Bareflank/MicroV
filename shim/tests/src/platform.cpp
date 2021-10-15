/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#include <mv_types.h>
#include <platform.h>
#include <string.h>

#include <bsl/convert.hpp>
#include <bsl/ensures.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace shim
{
    /// @brief tells platform_alloc to fail
    extern "C" bool g_mut_platform_alloc_fails{};    // NOLINT
    /// @brief tells platform_virt_to_phys_user to fail
    extern "C" bool g_mut_platform_virt_to_phys_user_fails{};    // NOLINT
    /// @brief number of online cpus
    extern "C" bsl::safe_u32 g_mut_platform_num_online_cpus{1U};    // NOLINT
    /// @brief return value for g_mut_platform_mlock
    extern "C" int64_t g_mut_platform_mlock{SHIM_SUCCESS};    // NOLINT
    /// @brief return value for g_mut_platform_mlock
    extern "C" int64_t g_mut_platform_munlock{SHIM_SUCCESS};    // NOLINT
    /// @brief tells platform_interrupted to return interrupted
    extern "C" bool g_mut_platform_interrupted{};    // NOLINT

    /// <!-- description -->
    ///   @brief If test is false, a contract violation has occurred. This
    ///     should be used to assert preconditions that if not meet, would
    ///     result in undefined behavior. These should not be tested by a
    ///     unit test, meaning they are contract violations. These asserts
    ///     are simply there as a sanity check during a debug build.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test the contract to check
    ///
    extern "C" void
    platform_expects(bsl::int32 const test) noexcept
    {
        bsl::expects(0 != test);    // GRCOV_EXCLUDE_BR
    }

    /// <!-- description -->
    ///   @brief If test is false, a contract violation has occurred. This
    ///     should be used to assert postconditions that if not meet, would
    ///     result in undefined behavior. These should not be tested by a
    ///     unit test, meaning they are contract violations. These asserts
    ///     are simply there as a sanity check during a debug build.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test the contract to check
    ///
    extern "C" void
    platform_ensures(bsl::int32 const test) noexcept
    {
        bsl::ensures(0 != test);    // GRCOV_EXCLUDE_BR
    }

    /// <!-- description -->
    ///   @brief This function allocates read/write virtual memory from the
    ///     kernel. This memory is not physically contiguous. The resulting
    ///     pointer is at least 4k aligned, so use this function sparingly
    ///     as it will always allocate at least one page. Use platform_free()
    ///     to release this memory.
    ///
    ///   @note This function must zero the allocated memory
    ///
    /// <!-- inputs/outputs -->
    ///   @param size the number of bytes to allocate
    ///   @return Returns a pointer to the newly allocated memory on success.
    ///     Returns a nullptr on failure.
    ///
    extern "C" NODISCARD void *
    platform_alloc(bsl::uint64 const size) noexcept
    {
        bsl::expects(bsl::safe_u64::magic_0() != size);

        if (g_mut_platform_alloc_fails) {
            return nullptr;
        }

        return new bsl::uint8[size]();
    }

    /// <!-- description -->
    ///   @brief This function frees memory previously allocated using the
    ///     platform_alloc() function.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_ptr the pointer returned by platform_alloc(). If ptr is
    ///     passed a nullptr, it will be ignored. Attempting to free memory
    ///     more than once results in UB.
    ///   @param size the number of bytes that were allocated. Note that this
    ///     may or may not be ignored depending on the platform.
    ///
    extern "C" void
    platform_free(void *const pmut_ptr, bsl::uint64 const size) noexcept
    {
        (void)size;

        if (nullptr != pmut_ptr) {
            delete[] static_cast<bsl::uint8 *>(pmut_ptr);    // GRCOV_EXCLUDE_BR
        }
    }

    /// <!-- description -->
    ///   @brief Given a virtual address, this function returns the virtual
    ///     address's physical address. Returns nullptr if the conversion failed.
    ///
    /// <!-- inputs/outputs -->
    ///   @param virt the virtual address to convert to a physical address
    ///   @return Given a virtual address, this function returns the virtual
    ///     address's physical address. Returns nullptr if the conversion failed.
    ///
    extern "C" [[nodiscard]] auto
    platform_virt_to_phys(void const *const virt) noexcept -> bsl::uintmx
    {
        return reinterpret_cast<bsl::uintmx>(virt);
    }

    /// <!-- description -->
    ///   @brief Given a virtual address, this function returns the virtual
    ///     address's physical address. Returns nullptr if the conversion failed.
    ///
    /// <!-- inputs/outputs -->
    ///   @param virt the virtual address to convert to a physical address
    ///   @return Given a virtual address, this function returns the virtual
    ///     address's physical address. Returns nullptr if the conversion failed.
    ///
    extern "C" [[nodiscard]] auto
    platform_virt_to_phys_user(uintptr_t const virt) noexcept -> bsl::uintmx
    {
        if (g_mut_platform_virt_to_phys_user_fails) {
            return {};
        }

        return virt;
    }

    /// <!-- description -->
    ///   @brief Sets "num" bytes in the memory pointed to by "ptr" to "val".
    ///     If the provided parameters are valid, returns 0, otherwise
    ///     returns SHIM_FAILURE.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_ptr a pointer to the memory to set
    ///   @param val the value to set each byte to
    ///   @param num the number of bytes in "pmut_ptr" to set to "val".
    ///
    extern "C" void
    platform_memset(void *const pmut_ptr, bsl::uint8 const val, bsl::uint64 const num) noexcept
    {
        bsl::expects(nullptr != pmut_ptr);
        memset(pmut_ptr, static_cast<bsl::int32>(val), num);    // NOLINT
    }

    /// <!-- description -->
    ///   @brief Copies "num" bytes from "src" to "pmut_dst". If "src" or "pmut_dst" are
    ///     nullptr, returns SHIM_FAILURE, otherwise returns 0.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_dst a pointer to the memory to copy to
    ///   @param src a pointer to the memory to copy from
    ///   @param num the number of bytes to copy
    ///
    extern "C" void
    platform_memcpy(void *const pmut_dst, void const *const src, bsl::uint64 const num) noexcept
    {
        bsl::expects(nullptr != pmut_dst);
        bsl::expects(nullptr != src);

        memcpy(pmut_dst, src, num);    // NOLINT
    }

    /// <!-- description -->
    ///   @brief Locks the pages within a memory region starting at
    ///     "pmut_ptr" and continuing for "num" bytes. Once locked, the
    ///     memory is guaranteed to never be paged out to disk.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_ptr a pointer to the memory to lock
    ///   @param num the number of bytes to lock.
    ///   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
    ///
    extern "C" [[nodiscard]] auto
    platform_mlock(void *const pmut_ptr, uint64_t const num) noexcept -> int64_t
    {
        bsl::expects(nullptr != pmut_ptr);
        bsl::expects(bsl::safe_u64::magic_0() != num);

        return g_mut_platform_mlock;
    }

    /// <!-- description -->
    ///   @brief Unlocks the pages within a memory region starting at
    ///     "pmut_ptr" and continuing for "num" bytes. Once unlocked, the
    ///     memory is allowed to be paged out to disk.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_ptr a pointer to the memory to unlock
    ///   @param num the number of bytes to unlock.
    ///   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
    ///
    extern "C" [[nodiscard]] auto
    platform_munlock(void *const pmut_ptr, uint64_t const num) noexcept -> int64_t
    {
        bsl::expects(nullptr != pmut_ptr);
        bsl::expects(bsl::safe_u64::magic_0() != num);

        return g_mut_platform_munlock;
    }

    /// <!-- description -->
    ///   @brief Copies "num" bytes from "src" to "pmut_dst". Returns
    ///     SHIM_SUCCESS on success, SHIM_FAILURE on failure.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_dst a pointer to the memory to copy to
    ///   @param src a pointer to the memory to copy from
    ///   @param num the number of bytes to copy
    ///   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
    ///
    extern "C" [[nodiscard]] auto
    platform_copy_from_user(
        void *const pmut_dst, void const *const src, uint64_t const num) noexcept -> int64_t
    {
        bsl::expects(nullptr != pmut_dst);
        bsl::expects(nullptr != src);

        memcpy(pmut_dst, src, num);    // NOLINT
        return SHIM_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Copies "num" bytes from "src" to "pmut_dst". Returns
    ///     SHIM_SUCCESS on success, SHIM_FAILURE on failure.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_dst a pointer to the memory to copy to
    ///   @param src a pointer to the memory to copy from
    ///   @param num the number of bytes to copy
    ///   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
    ///
    extern "C" [[nodiscard]] auto
    platform_copy_to_user(void *const pmut_dst, void const *const src, uint64_t const num) noexcept
        -> int64_t
    {
        bsl::expects(nullptr != pmut_dst);
        bsl::expects(nullptr != src);

        memcpy(pmut_dst, src, num);    // NOLINT
        return SHIM_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Returns the total number of online CPUs (i.e. PPs)
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the total number of online CPUs (i.e. PPs)
    ///
    extern "C" [[nodiscard]] auto
    platform_num_online_cpus(void) noexcept -> bsl::uint32
    {
        return g_mut_platform_num_online_cpus.get();
    }

    /// <!-- description -->
    ///   @brief Returns the current CPU (i.e. PP)
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the current CPU (i.e. PP)
    ///
    extern "C" [[nodiscard]] auto
    platform_current_cpu(void) noexcept -> bsl::uint32
    {
        return 0U;
    }

    /// <!-- description -->
    ///   @brief Calls the user provided callback on each CPU. If each callback
    ///     returns 0, this function returns 0, otherwise this function returns
    ///     a non-0 value, even if all callbacks succeed except for one. If an
    ///     error occurs, it is possible that this function will continue to
    ///     execute the remaining callbacks until all callbacks have been called
    ///     (depends on the platform).
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_func the function to call on each cpu
    ///   @param order sets the order the CPUs are called
    ///   @return If each callback returns 0, this function returns 0, otherwise
    ///     this function returns a non-0 value
    ///
    extern "C" [[nodiscard]] auto
    platform_on_each_cpu(platform_per_cpu_func const pmut_func, bsl::uint32 const order) noexcept
        -> bsl::int64
    {
        (void)order;
        return pmut_func(0U);
    }

    /// <!-- description -->
    ///   @brief Initializes a mutex lock. This must be called before a
    ///     mutex can be used.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_mutex the mutex to lock
    ///
    extern "C" void
    // NOLINTNEXTLINE(readability-non-const-parameter)
    platform_mutex_init(platform_mutex *const pmut_mutex) noexcept
    {
        (void)pmut_mutex;
    }

    /// <!-- description -->
    ///   @brief Locks a mutex object. The mutex object must be initialized
    ///     using platform_mutex_init before it is used.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_mutex the mutex to lock
    ///
    extern "C" void
    // NOLINTNEXTLINE(readability-non-const-parameter)
    platform_mutex_lock(platform_mutex *const pmut_mutex) noexcept
    {
        (void)pmut_mutex;
    }

    /// <!-- description -->
    ///   @brief Unlocks a mutex object. The mutex object must be initialized
    ///     using platform_mutex_init before it is used.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_mutex the mutex to unlock
    ///
    extern "C" void
    // NOLINTNEXTLINE(readability-non-const-parameter)
    platform_mutex_unlock(platform_mutex *const pmut_mutex) noexcept
    {
        (void)pmut_mutex;
    }

    /// <!-- description -->
    ///   @brief Returns SHIM_SUCCESS if the current process has NOT been
    ///     interrupted. Returns SHIM_FAILURE otherwise.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns SHIM_SUCCESS if the current process has NOT been
    ///     interrupted. Returns SHIM_FAILURE otherwise.
    ///
    extern "C" [[nodiscard]] auto
    platform_interrupted() noexcept -> int64_t
    {
        if (g_mut_platform_interrupted) {
            return SHIM_INTERRUPTED;
        }

        return SHIM_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Returns the TSC frequency of the PP this is called on
    ///     in KHz.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns the TSC frequency of the PP this is called on
    ///     in KHz.
    ///
    extern "C" [[nodiscard]] auto
    platform_tsc_khz() noexcept -> uint64_t
    {
        constexpr auto tsc_khz{42_u64};
        return tsc_khz.get();
    }
}
