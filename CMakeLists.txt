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

include(${MICROV_SOURCE_CMAKE_DIR}/targets.cmake)

if(ENABLE_BUILD_VMM)
    add_subproject(
        uvvmm vmm
        DEPENDS bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/vmm
    )

    if(ENABLE_BUILD_EFI)
        message(STATUS "    efi binary to boot after bareflank.efi: ${EFI_BOOT_NEXT}")
    endif()

    message(STATUS "    build xen components: ${BUILD_XEN}")
    message(STATUS "    use xue usb debugger: ${USE_XUE}")
endif()

if(ENABLE_BUILD_USERSPACE)
    add_subproject(
        uvctl userspace
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/uvctl
        DEPENDS bfintrinsics
        DEPENDS bfsdk
        DEPENDS cxxopts
    )
endif()
