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

if(ENABLE_BUILD_VMM)
    message(STATUS "Including dependency: capstone")

    download_dependency(
        capstone
        URL         ${CAPSTONE_URL}
        URL_MD5     ${CAPSTONE_URL_MD5}
    )

    generate_flags(
        vmm
        NOWARNINGS
    )

    list(APPEND CAPSTONE_CONFIGURE_FLAGS
        -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF
        -DCAPSTONE_BUILD_CSTOOL=OFF
        -DCAPSTONE_BUILD_SHARED=OFF
        -DCAPSTONE_BUILD_STATIC=ON
        -DCAPSTONE_BUILD_STATIC_RUNTIME=OFF
        -DCAPSTONE_BUILD_TESTS=OFF
        -DCAPSTONE_X86_ATT_DISABLE=ON
        -DCAPSTONE_X86_REDUCE=ON
        -DCAPSTONE_X86_SUPPORT=ON
        -DCMAKE_TOOLCHAIN_FILE=${VMM_TOOLCHAIN_PATH}
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    )

    add_dependency(
        capstone vmm
        CMAKE_ARGS  ${CAPSTONE_CONFIGURE_FLAGS}
        DEPENDS     libcxxabi_${VMM_PREFIX}
        DEPENDS     libcxx_${VMM_PREFIX}
        DEPENDS     newlib_${VMM_PREFIX}
    )
endif()
