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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Including dependency: linux")

    FetchContent_Declare(
        linux
        URL         https://github.com/Bareflank/linux/archive/boxy_1.02.zip
        URL_MD5     bbe9d03b76f874444ff2839f74c982e6
    )

    FetchContent_GetProperties(linux)
    if(NOT linux_POPULATED)
        FetchContent_Populate(linux)
        execute_process(COMMAND ${CMAKE_COMMAND} -E copy_directory ${linux_SOURCE_DIR} ${linux_BINARY_DIR})
    endif()

        # add_dependency_step(
        #     linux-source userspace
        #     COMMAND ${CMAKE_COMMAND} -E make_directory ${LINUX_BUILD_DIR}
        #     COMMAND ${CMAKE_COMMAND} -E copy_directory ${CACHE_DIR}/linux-source/ ${LINUX_BUILD_DIR}
        #     COMMAND ${CMAKE_COMMAND} -E copy ${BOXY_SOURCE_ROOT_DIR}/bflinux/config ${LINUX_BUILD_DIR}/.config
        #     COMMAND ${CMAKE_COMMAND} -E chdir ${LINUX_BUILD_DIR} make oldconfig
        #     COMMAND ${CMAKE_COMMAND} -E make_directory ${PREFIXES_DIR}/vms/
        # )

        # add_dependency_step(
        #     linux-source userspace
        #     COMMAND ${CMAKE_COMMAND} -E copy ${BOXY_SOURCE_ROOT_DIR}/bflinux/config ${LINUX_BUILD_DIR}/.config
        #     COMMAND ${CMAKE_COMMAND} -E chdir ${LINUX_BUILD_DIR} make oldconfig
        #     COMMAND ${CMAKE_COMMAND} -E make_directory ${PREFIXES_DIR}/vms/
        # )


        # add_dependency_step(
        #     linux userspace
        #     COMMAND ${CMAKE_COMMAND} -E chdir ${LINUX_BUILD_DIR} make ARCH=x86_64 -j${BUILD_TARGET_CORES}
        #     COMMAND ${CMAKE_COMMAND} -E copy ${LINUX_BUILD_DIR}/arch/x86/boot/bzImage ${PREFIXES_DIR}/vms/
        # )

endif()
