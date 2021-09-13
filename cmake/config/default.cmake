#
# Copyright (C) 2020 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

include(${bsl_SOURCE_DIR}/cmake/function/bf_add_config.cmake)

option(MICROV_BUILD_HYPERCALL "Turns on/off building the hypercall library" ON)
option(MICROV_BUILD_SHIM "Turns on/off building the shim" ON)
option(MICROV_BUILD_VMM "Turns on/off building the vmm" ON)

bf_add_config(
    CONFIG_NAME MICROV_MAX_VCPUS
    CONFIG_TYPE STRING
    DEFAULT_VAL "${HYPERVISOR_MAX_PPS}"
    DESCRIPTION "Defines MicroV's max number of KVM VCPUs per VM that are supported"
    SKIP_VALIDATION
)

bf_add_config(
    CONFIG_NAME MICROV_MAX_PP_MAPS
    CONFIG_TYPE STRING
    DEFAULT_VAL "150"
    DESCRIPTION "Defines MicroV's max number of maps each PP can have open at any given time"
    SKIP_VALIDATION
)
