#
# Copyright (C) 2018 Assured Information Security, Inc.
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
# Source Tree
# ------------------------------------------------------------------------------

set(HK_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..
    CACHE INTERNAL
    "Hyperkernel Source root direfctory"
)

set(HK_SOURCE_CMAKE_DIR ${HK_SOURCE_ROOT_DIR}/scripts/cmake
    CACHE INTERNAL
    "Hyperkernel Cmake directory"
)

set(HK_SOURCE_CONFIG_DIR ${HK_SOURCE_ROOT_DIR}/scripts/cmake/config
    CACHE INTERNAL
    "Hyperkernel Cmake configurations directory"
)

set(HK_SOURCE_DEPENDS_DIR ${HK_SOURCE_ROOT_DIR}/scripts/cmake/depends
    CACHE INTERNAL
    "Hyperkernel Cmake dependencies directory"
)

set(HK_SOURCE_UTIL_DIR ${HK_SOURCE_ROOT_DIR}/scripts/util
    CACHE INTERNAL
    "Hyperkernel Utility directory"
)

set(HK_SOURCE_BFDRIVER_DIR ${HK_SOURCE_ROOT_DIR}/bfdriver
    CACHE INTERNAL
    "Hyperkernel bfdriver source dir"
)

set(HK_SOURCE_BFEXEC_DIR ${HK_SOURCE_ROOT_DIR}/bfexec
    CACHE INTERNAL
    "Hyperkernel bfexec source dir"
)

set(HK_SOURCE_BFLINUX_DIR ${HK_SOURCE_ROOT_DIR}/bflinux
    CACHE INTERNAL
    "Hyperkernel bflinux source dir"
)

set(HK_SOURCE_BFSDK_DIR ${HK_SOURCE_ROOT_DIR}/bfsdk
    CACHE INTERNAL
    "Hyperkernel bfsdk source dir"
)

set(HK_SOURCE_BFVMM_DIR ${HK_SOURCE_ROOT_DIR}/bfvmm
    CACHE INTERNAL
    "Hyperkernel bfvmm source dir"
)

# ------------------------------------------------------------------------------
# Links
# ------------------------------------------------------------------------------

set(LINUX_URL "https://github.com/Bareflank/linux/archive/v4.19.zip"
    CACHE INTERNAL FORCE
    "Linux URL"
)

set(LINUX_URL_MD5 "3a2b3db4760402c650cabc2daac7b388"
    CACHE INTERNAL FORCE
    "Linux URL MD5 hash"
)
