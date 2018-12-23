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

cmake_minimum_required(VERSION 3.6)
project(bfexec C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../../bfvmm/include
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../../bfsdk/include
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../include
)

if(BUILD_TARGET_OS STREQUAL "Linux")
    list(APPEND SOURCES
        platform/linux/ioctl.cpp
        platform/linux/ioctl_private.cpp
    )
    include_directories(platform/linux/)
elseif(BUILD_TARGET_OS STREQUAL "Windows")
    list(APPEND SOURCES
        platform/windows/ioctl.cpp
        platform/windows/ioctl_private.cpp
    )
    include_directories(platform/windows/)
else()
    message(FATAL_ERROR "Unsupported OS: ${BUILD_TARGET_OS}")
endif()

list(APPEND SOURCES
    main.cpp
)

add_executable(bfexec ${SOURCES})
target_link_static_libraries(bfexec bfintrinsics)

if(CYGWIN OR WIN32)
    target_link_libraries(bfexec setupapi)
endif()

if(UNIX)
    target_link_libraries(bfexec pthread)
endif()

install(TARGETS bfexec DESTINATION bin)
