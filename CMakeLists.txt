#
# Copyright (C) 2019 Assured Information Security, Inc.
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

# ------------------------------------------------------------------------------
# Project includes
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/config/default.cmake)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

include(${BOXY_SOURCE_CMAKE_DIR}/targets.cmake)

# ------------------------------------------------------------------------------
# General Dependencies
# ------------------------------------------------------------------------------

include_dependency(BOXY_SOURCE_DEPENDS_DIR linux)

# ------------------------------------------------------------------------------
# VMM
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_VMM)
    vmm_extension(
        boxy_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
    )

    vmm_extension(
        boxy_bfvmm_main
        DEPENDS boxy_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
    )
endif()

# ------------------------------------------------------------------------------
# bfexec
# ------------------------------------------------------------------------------

userspace_extension(
    bfexec
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfexec/src
    DEPENDS bfintrinsics
    DEPENDS cxxopts
)

# ------------------------------------------------------------------------------
# bflinux
# ------------------------------------------------------------------------------

if(NOT WIN32 AND NOT CYGWIN)
    userspace_extension(
        bflinux
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bflinux
        DEPENDS bfintrinsics
    )
endif()
