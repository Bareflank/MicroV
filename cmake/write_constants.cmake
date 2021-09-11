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

if(EXISTS ${CMAKE_BINARY_DIR}/include/constants.h)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/include)
    set(HYPERVISOR_CONSTANTS ${CMAKE_BINARY_DIR}/include/constants.h)

    file(APPEND ${HYPERVISOR_CONSTANTS} "\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "/* ---- AUTO GENERATED FROM MICROV ---- */\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "\n")

    file(APPEND ${HYPERVISOR_CONSTANTS} "#ifndef CONSTANTS_FROM_MICROV_H\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "#define CONSTANTS_FROM_MICROV_H\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "\n")

    file(APPEND ${HYPERVISOR_CONSTANTS} "#define MICROV_MAX_VCPUS ((uint64_t)(${MICROV_MAX_VCPUS}))\n")
    file(APPEND ${HYPERVISOR_CONSTANTS} "\n")

    file(APPEND ${HYPERVISOR_CONSTANTS} "#endif\n")
else()
    message(FATAL_ERROR "HYPERVISOR_CONSTANTS missing")
endif()
