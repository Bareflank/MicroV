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

set(BOXY_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..
    CACHE INTERNAL
    "BOXY Source root direfctory"
)

set(BOXY_SOURCE_CMAKE_DIR ${BOXY_SOURCE_ROOT_DIR}/scripts/cmake
    CACHE INTERNAL
    "BOXY Cmake directory"
)

set(BOXY_SOURCE_CONFIG_DIR ${BOXY_SOURCE_ROOT_DIR}/scripts/cmake/config
    CACHE INTERNAL
    "BOXY Cmake configurations directory"
)

set(BOXY_SOURCE_DEPENDS_DIR ${BOXY_SOURCE_ROOT_DIR}/scripts/cmake/depends
    CACHE INTERNAL
    "BOXY Cmake dependencies directory"
)

set(BOXY_SOURCE_UTIL_DIR ${BOXY_SOURCE_ROOT_DIR}/scripts/util
    CACHE INTERNAL
    "BOXY Utility directory"
)

set(BOXY_SOURCE_BFDRIVER_DIR ${BOXY_SOURCE_ROOT_DIR}/bfdriver
    CACHE INTERNAL
    "BOXY bfdriver source dir"
)

set(BOXY_SOURCE_BFEXEC_DIR ${BOXY_SOURCE_ROOT_DIR}/bfexec
    CACHE INTERNAL
    "BOXY bfexec source dir"
)

set(BOXY_SOURCE_BFLINUX_DIR ${BOXY_SOURCE_ROOT_DIR}/bflinux
    CACHE INTERNAL
    "BOXY bflinux source dir"
)

set(BOXY_SOURCE_BFSDK_DIR ${BOXY_SOURCE_ROOT_DIR}/bfsdk
    CACHE INTERNAL
    "BOXY bfsdk source dir"
)

set(BOXY_SOURCE_BFVMM_DIR ${BOXY_SOURCE_ROOT_DIR}/bfvmm
    CACHE INTERNAL
    "BOXY bfvmm source dir"
)

# ------------------------------------------------------------------------------
# Links
# ------------------------------------------------------------------------------

set(LINUX_URL "https://github.com/Bareflank/linux/archive/boxy_1.zip"
    CACHE INTERNAL FORCE
    "Linux URL"
)

set(LINUX_URL_MD5 "481f81505b4f73349e501f70c15a4946"
    CACHE INTERNAL FORCE
    "Linux URL MD5 hash"
)
