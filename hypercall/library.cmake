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

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/function/microv_target_source.cmake)

add_library(hypercall)

# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(hypercall PUBLIC
            include/x64/amd
            src/x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(hypercall PUBLIC
            include/x64/intel
            src/x64/intel
        )
    endif()

    target_include_directories(hypercall PUBLIC
        include/x64
        src/x64
    )
endif()

target_include_directories(hypercall PUBLIC
    include
    src
)

# ------------------------------------------------------------------------------
# Headers
# ------------------------------------------------------------------------------

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_constants.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_translation_t.hpp
    ${CMAKE_CURRENT_LIST_DIR}/include/mv_types.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_debug_ops.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_hypercall_impl.hpp
    ${CMAKE_CURRENT_LIST_DIR}/src/mv_hypercall_t.hpp
)

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/amd/mv_reg_t.hpp
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        list(APPEND HEADERS
            ${CMAKE_CURRENT_LIST_DIR}/include/x64/intel/mv_reg_t.hpp
        )
    endif()
endif()

# ------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------

if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD" OR HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        microv_target_source(hypercall src/linux/x64/amd/mv_debug_op_out_impl.S ${HEADERS})
        microv_target_source(hypercall src/linux/x64/amd/mv_handle_op_close_handle_impl.S ${HEADERS})
        microv_target_source(hypercall src/linux/x64/amd/mv_handle_op_open_handle_impl.S ${HEADERS})
        microv_target_source(hypercall src/linux/x64/amd/mv_id_op_version_impl.S ${HEADERS})
        # microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_gla_to_gpa_impl.S ${HEADERS})
        # microv_target_source(hypercall src/linux/x64/amd/mv_vs_op_gva_to_gla_impl.S ${HEADERS})
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        microv_target_source(hypercall src/linux/x64/intel/mv_debug_op_out_impl.S ${HEADERS})
        microv_target_source(hypercall src/linux/x64/intel/mv_handle_op_close_handle_impl.S ${HEADERS})
        microv_target_source(hypercall src/linux/x64/intel/mv_handle_op_open_handle_impl.S ${HEADERS})
        microv_target_source(hypercall src/linux/x64/intel/mv_id_op_version_impl.S ${HEADERS})
        # microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_gla_to_gpa_impl.S ${HEADERS})
        # microv_target_source(hypercall src/linux/x64/intel/mv_vs_op_gva_to_gla_impl.S ${HEADERS})
    endif()
endif()

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

target_link_libraries(hypercall PUBLIC
    bsl
    hypervisor
)

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(TARGETS hypercall DESTINATION lib)
