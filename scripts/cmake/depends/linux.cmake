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

# README
#
# By default, the build system will download a Boxy release version of the Linux
# kernel (specifically the current, stable release). For most users, this is
# enough and no action is required for this default functionalilty.
#
# If you are a developer fixing a bug with Linux, or adding additional
# functionality to the Linux kernel, you can use your own, custom Linux kernel
# by setting the LINUX_DIR variable in your config, or on the command line
# when configuring CMake. This will redirect the build system to use your Linux
# kernel.
#
# All changes upstreamed to the Boxy version of the Linux kernel will be
# roled into the main release once the boxy master branches are stable. From
# there, upstreaming to the main Linux kernel can be done.
#

if((ENABLE_BUILD_USERSPACE) AND NOT WIN32 AND NOT CYGWIN)
    message(STATUS "Including dependency: linux")

    if(NOT DEFINED LINUX_DIR)
        if(EXISTS ${CMAKE_SOURCE_DIR}/../linux/)
            set(LINUX_DIR PATH ${CMAKE_SOURCE_DIR}/../linux/)
        endif()
    endif()

    if(NOT DEFINED LINUX_DIR)
        set(LINUX_BUILD_DIR ${DEPENDS_DIR}/linux/${USERSPACE_PREFIX}/build)

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
            DOWNLOAD_COMMAND    ${CMAKE_COMMAND} -E echo "-- skip"
        )

        add_dependency_step(
            linux-source userspace
            COMMAND ${CMAKE_COMMAND} -E make_directory ${LINUX_BUILD_DIR}
            COMMAND ${CMAKE_COMMAND} -E copy_directory ${CACHE_DIR}/linux-source/ ${LINUX_BUILD_DIR}
            COMMAND ${CMAKE_COMMAND} -E copy ${BOXY_SOURCE_ROOT_DIR}/bflinux/config ${LINUX_BUILD_DIR}/.config
            COMMAND ${CMAKE_COMMAND} -E chdir ${LINUX_BUILD_DIR} make oldconfig
            COMMAND ${CMAKE_COMMAND} -E make_directory ${PREFIXES_DIR}/vms/
        )
    else()
        set(LINUX_BUILD_DIR ${LINUX_DIR})

        add_dependency(
            linux-source userspace
            CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E echo "-- skip"
            BUILD_COMMAND       ${CMAKE_COMMAND} -E echo "-- skip"
            INSTALL_COMMAND     ${CMAKE_COMMAND} -E echo "-- skip"
            DOWNLOAD_COMMAND    ${CMAKE_COMMAND} -E echo "-- skip"
        )

        add_dependency_step(
            linux-source userspace
            COMMAND ${CMAKE_COMMAND} -E copy ${BOXY_SOURCE_ROOT_DIR}/bflinux/config ${LINUX_BUILD_DIR}/.config
            COMMAND ${CMAKE_COMMAND} -E chdir ${LINUX_BUILD_DIR} make oldconfig
            COMMAND ${CMAKE_COMMAND} -E make_directory ${PREFIXES_DIR}/vms/
        )

        message("--     linux directory: ${LINUX_DIR}")
    endif()

    add_dependency(
        linux userspace
        CONFIGURE_COMMAND   ${CMAKE_COMMAND} -E echo "-- skip"
        BUILD_COMMAND       ${CMAKE_COMMAND} -E echo "-- skip"
        INSTALL_COMMAND     ${CMAKE_COMMAND} -E echo "-- skip"
        DOWNLOAD_COMMAND    ${CMAKE_COMMAND} -E echo "-- skip"
        UPDATE_COMMAND      ${CMAKE_COMMAND} -E echo "-- checking for updates"
        DEPENDS             linux-source_${USERSPACE_PREFIX}
    )

    add_dependency_step(
        linux userspace
        COMMAND ${CMAKE_COMMAND} -E chdir ${LINUX_BUILD_DIR} make ARCH=x86_64 -j${BUILD_TARGET_CORES}
        COMMAND ${CMAKE_COMMAND} -E copy ${LINUX_BUILD_DIR}/arch/x86/boot/bzImage ${PREFIXES_DIR}/vms/
    )

    add_custom_target(vms DEPENDS linux_${USERSPACE_PREFIX})
endif()
