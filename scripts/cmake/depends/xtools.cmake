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

if(NOT BUILD_XEN_GUEST OR WIN32)
    return()
endif()

message(STATUS "Including dependency: xtools")

if(NOT DEFINED XTOOLS_DIR)
    set(XTOOLS_DIR ${CACHE_DIR}/xtools)

    download_dependency(
        xtools
        URL         ${XTOOLS_URL}
        URL_MD5     ${XTOOLS_URL_MD5}
    )

    add_dependency(
        xtools userspace
        DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E touch_nocreate foo
        CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${XTOOLS_DIR} ./relocate-sdk.sh
        BUILD_COMMAND ${CMAKE_COMMAND} -E touch_nocreate foo
        INSTALL_COMMAND ${CMAKE_COMMAND} -E touch_nocreate foo
    )
endif()