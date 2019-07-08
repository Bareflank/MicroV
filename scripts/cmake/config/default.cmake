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
# Source Tree
# ------------------------------------------------------------------------------

set(MICROV_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..
    CACHE INTERNAL
    "MICROV Source root direfctory"
)

set(MICROV_SOURCE_CMAKE_DIR ${MICROV_SOURCE_ROOT_DIR}/scripts/cmake
    CACHE INTERNAL
    "MICROV Cmake directory"
)

set(MICROV_SOURCE_CONFIG_DIR ${MICROV_SOURCE_ROOT_DIR}/scripts/cmake/config
    CACHE INTERNAL
    "MICROV Cmake configurations directory"
)

set(MICROV_SOURCE_DEPENDS_DIR ${MICROV_SOURCE_ROOT_DIR}/scripts/cmake/depends
    CACHE INTERNAL
    "MICROV Cmake dependencies directory"
)

set(MICROV_SOURCE_UTIL_DIR ${MICROV_SOURCE_ROOT_DIR}/scripts/util
    CACHE INTERNAL
    "MICROV Utility directory"
)

set(MICROV_SOURCE_BFDRIVER_DIR ${MICROV_SOURCE_ROOT_DIR}/bfdriver
    CACHE INTERNAL
    "MICROV bfdriver source dir"
)

set(MICROV_SOURCE_BFEXEC_DIR ${MICROV_SOURCE_ROOT_DIR}/bfexec
    CACHE INTERNAL
    "MICROV bfexec source dir"
)

set(MICROV_SOURCE_BFLINUX_DIR ${MICROV_SOURCE_ROOT_DIR}/bflinux
    CACHE INTERNAL
    "MICROV bflinux source dir"
)

set(MICROV_SOURCE_BFSDK_DIR ${MICROV_SOURCE_ROOT_DIR}/bfsdk
    CACHE INTERNAL
    "MICROV bfsdk source dir"
)

set(MICROV_SOURCE_BFVMM_DIR ${MICROV_SOURCE_ROOT_DIR}/bfvmm
    CACHE INTERNAL
    "MICROV bfvmm source dir"
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

set(XTOOLS_URL "https://github.com/connojd/xtools/releases/download/v0.8.0/xtools.tar.gz"
    CACHE INTERNAL FORCE
    "xtools URL"
)

set(XTOOLS_URL_MD5 "d025f4ad293a51ed77831d3e1245af62"
    CACHE INTERNAL FORCE
    "xtools URL MD5"
)

# ------------------------------------------------------------------------------
# MicroV guest
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME ENABLE_BUILD_GUEST
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Build a minimal Linux guest along with the VMM"
)
