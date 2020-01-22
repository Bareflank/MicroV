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

set(MICROV_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..
    CACHE INTERNAL
    "Microv root directory"
)

set(MICROV_SOURCE_CMAKE_DIR ${MICROV_SOURCE_ROOT_DIR}/scripts/cmake
    CACHE INTERNAL
    "Microv cmake scripts directory"
)

set(MICROV_SOURCE_DEPS_DIR ${MICROV_SOURCE_ROOT_DIR}/deps
    CACHE INTERNAL
    "Microv concurrently-developed dependencies directory"
)

set(MICROV_SOURCE_DEPENDS_DIR ${MICROV_SOURCE_ROOT_DIR}/scripts/cmake/depends
    CACHE INTERNAL
    "Microv static dependencies directory"
)

set(MICROV_SOURCE_UTIL_DIR ${MICROV_SOURCE_ROOT_DIR}/scripts/util
    CACHE INTERNAL
    "Microv utility scripts directory"
)

set(LINUX_URL "https://github.com/Bareflank/linux/archive/boxy_1.zip"
    CACHE INTERNAL FORCE
    "Linux URL"
)

set(LINUX_URL_MD5 "481f81505b4f73349e501f70c15a4946"
    CACHE INTERNAL FORCE
    "Linux URL MD5 hash"
)

set(XTOOLS_URL "https://github.com/connojd/xtools/releases/download/v0.9.0/xtools.tar.gz"
    CACHE INTERNAL FORCE
    "xtools URL"
)

set(XTOOLS_URL_MD5 "3b9e77e10c5764657bfb8e168b7c23b5"
    CACHE INTERNAL FORCE
    "xtools URL MD5"
)

set(BR_OVERLAY_DIR ${MICROV_SOURCE_ROOT_DIR}/overlays)
set(BR_SRC_DIR ${MICROV_SOURCE_ROOT_DIR}/deps/buildroot)
set(BR_BIN_DIR ${CACHE_DIR}/brbuild)

add_config(
    CONFIG_NAME BUILD_XENPVH_GUEST
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Build a Xen PVH guest"
)

add_config(
    CONFIG_NAME GRAPH_GUEST_IMAGES
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Make targets to graph guest filesystem info"
)

add_config(
    CONFIG_NAME BUILD_BUILDER
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Build driver for running guest VMs"
)

add_config(
    CONFIG_NAME BUILD_VISR
    CONFIG_TYPE BOOL
    DEFAULT_VAL OFF
    DESCRIPTION "Build driver for PCI passthrough"
)
