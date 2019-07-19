//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef MICROV_IOMMU_REGS_H
#define MICROV_IOMMU_REGS_H

#include <bftypes.h>

namespace microv::iommu_regs {

/* Register offsets from the base address */
constexpr auto ver_offset = 0x00U;
constexpr auto cap_offset = 0x08U;
constexpr auto ecap_offset = 0x10U;
constexpr auto gcmd_offset = 0x18U;
constexpr auto gsts_offset = 0x1CU;
constexpr auto rtaddr_offset = 0x20U;
constexpr auto ccmd_offset = 0x28U;

/*
 * Register fields. Each field has a mask and a "from" value used
 * to shift the masked value over
 */

constexpr auto ver_min_mask = 0xFU;
constexpr auto ver_min_from = 0;
constexpr auto ver_max_mask = 0xF0U;
constexpr auto ver_max_from = 4;

constexpr auto cap_nd_mask = 0x7U;
constexpr auto cap_nd_from = 0U;
constexpr auto cap_afl_mask = 0x8U;
constexpr auto cap_afl_from = 3U;
constexpr auto cap_rwbf_mask = 0x10U;
constexpr auto cap_rwbf_from = 4U;
constexpr auto cap_plmr_mask = 0x20U;
constexpr auto cap_plmr_from = 5U;
constexpr auto cap_phmr_mask = 0x40U;
constexpr auto cap_phmr_from = 6U;
constexpr auto cap_cm_mask = 0x80U;
constexpr auto cap_cm_from = 7U;
constexpr auto cap_sagaw_mask = 0x1F00U;
constexpr auto cap_sagaw_from = 8U;
constexpr auto cap_mgaw_mask = 0x3F0000U;
constexpr auto cap_mgaw_from = 16U;
constexpr auto cap_zlr_mask = 0x400000U;
constexpr auto cap_zlr_from = 22U;
constexpr auto cap_fro_mask = 0x3'FF00'0000U;
constexpr auto cap_fro_from = 24U;
constexpr auto cap_sllps_mask = 0x3C'00000000U;
constexpr auto cap_sllps_from = 34U;
constexpr auto cap_psi_mask = 0x80'00000000U;
constexpr auto cap_psi_from = 39U;
constexpr auto cap_nfr_mask = 0xFF'00'00000000U;
constexpr auto cap_nfr_from = 40U;
constexpr auto cap_mamv_mask = 0x3F'00'00'00000000U;
constexpr auto cap_mamv_from = 48U;
constexpr auto cap_dwd_mask = 0x40'00'00'00000000U;
constexpr auto cap_dwd_from = 54U;
constexpr auto cap_drd_mask = 0x80'00'00'00000000U;
constexpr auto cap_drd_from = 55U;
constexpr auto cap_fl1gp_mask = 0x01'00'00'00'00000000U;
constexpr auto cap_fl1gp_from = 56U;
constexpr auto cap_pi_mask = 0x0800'0000'00000000U;
constexpr auto cap_pi_from = 59U;
constexpr auto cap_fl5lp_mask = 0x1000'0000'00000000U;
constexpr auto cap_fl5lp_from = 60U;

constexpr auto ecap_c_mask = 0x1U;
constexpr auto ecap_c_from = 0U;
constexpr auto ecap_qi_mask = 0x2U;
constexpr auto ecap_qi_from = 1U;
constexpr auto ecap_dt_mask = 0x4U;
constexpr auto ecap_dt_from = 2U;
constexpr auto ecap_ir_mask = 0x8U;
constexpr auto ecap_ir_from = 3U;
constexpr auto ecap_eim_mask = 0x10U;
constexpr auto ecap_eim_from = 4U;
constexpr auto ecap_pt_mask = 0x40U;
constexpr auto ecap_pt_from = 6U;
constexpr auto ecap_sc_mask = 0x80U;
constexpr auto ecap_sc_from = 7U;
constexpr auto ecap_iro_mask = 0x3FF00U;
constexpr auto ecap_iro_from = 8U;

}

#endif
