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

if((ENABLE_BUILD_USERSPACE) AND NOT WIN32)
    message(STATUS "Including dependency: linux")

    download_dependency(
        linux-source
        URL         ${LINUX_URL}
        URL_MD5     ${LINUX_URL_MD5}
    )

    add_dependency(
        linux-source userspace
        CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E echo "-- skip"
        BUILD_COMMAND       ${CMAKE_COMMAND} -E echo "-- skip"
        INSTALL_COMMAND     ${CMAKE_COMMAND} -E echo "-- skip"
    )

    add_dependency_step(
        linux-source userspace
        COMMAND ${CMAKE_COMMAND} -E make_directory ${PREFIXES_DIR}/vms/
        COMMAND ${CMAKE_COMMAND} -E make_directory ${DEPENDS_DIR}/linux/${USERSPACE_PREFIX}/build
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CACHE_DIR}/linux/ ${DEPENDS_DIR}/linux/${USERSPACE_PREFIX}/build
        COMMAND ${CMAKE_COMMAND} -E copy ${HK_SOURCE_ROOT_DIR}/bflinux/config ${DEPENDS_DIR}/linux/${USERSPACE_PREFIX}/build/.config
    )

    add_dependency(
        linux userspace
        CONFIGURE_COMMAND   make oldconfig
        BUILD_COMMAND       make -j${BUILD_TARGET_CORES}
        INSTALL_COMMAND     ${CMAKE_COMMAND} -E copy ${DEPENDS_DIR}/linux/${USERSPACE_PREFIX}/build/vmlinux ${PREFIXES_DIR}/vms/
        DEPENDS             linux-source_${USERSPACE_PREFIX}
        UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "-- checking for updates"
    )

    add_custom_target(vms DEPENDS linux_${USERSPACE_PREFIX})
endif()
