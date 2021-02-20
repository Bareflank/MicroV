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

get_filename_component( MICROV_SOURCE_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE CACHE)
set(MICROV_SOURCE_ROOT_DIR ${MICROV_SOURCE_ROOT_DIR}
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

add_config(
    CONFIG_NAME EFI_BOOT_NEXT
    CONFIG_TYPE STRING
    DEFAULT_VAL "/EFI/boot/bootx64.efi"
    DESCRIPTION "Path (relative to ESP mount point) to EFI binary to boot after bareflank.efi"
)
