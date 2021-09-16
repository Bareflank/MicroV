/** 
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

#ifndef KVM_SEGMENT_H
#define KVM_SEGMENT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

    /**
     * @struct kvm_segment
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_segment
    {
        /** @brief stores that value of the base segment register */
        uint64_t base;
        /** @brief stores that value of the limit segment register */
        uint32_t limit;
        /** @brief stores that value of the selector segment register */
        uint16_t selector;
        /** @brief stores that value of the type segment register */
        uint8_t type;
        /** @brief stores that value of the present segment register */
        uint8_t present;
        /** @brief stores that value of the dpl segment register */
        uint8_t dpl;
        /** @brief stores that value of the db segment register */
        uint8_t db;
        /** @brief stores that value of the s segment register */
        uint8_t s;
        /** @brief stores that value of the l segment register */
        uint8_t l;
        /** @brief stores that value of the g segment register */
        uint8_t g;
        /** @brief stores that value of the avl segment register */
        uint8_t avl;
        /** @brief stores that value of the unusable segment register */
        uint8_t unusable;
        /** @brief stores that value of the padding segment register */
        uint8_t padding;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
