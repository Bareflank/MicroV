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

# ------------------------------------------------------------------------------
# Clang Format
# ------------------------------------------------------------------------------

if(ENABLE_CLANG_FORMAT)
    add_custom_target(clang-format)

    # Build git ls-files command line argument
    file(STRINGS "${MICROV_SOURCE_ROOT_DIR}/.gitsubtrees" GIT_SUBTREES)
    list(TRANSFORM GIT_SUBTREES PREPEND ":!:./")
    list(TRANSFORM GIT_SUBTREES APPEND "/*")

    # Find all *.h and *.cpp in git tracked files including untracked and cached
    # files but excluding git ignored files and submodules.
    execute_process(
        COMMAND git ls-files --cached --others --exclude-standard -- *.h *.cpp
                ${GIT_SUBTREES}
        WORKING_DIRECTORY ${MICROV_SOURCE_ROOT_DIR}
        RESULT_VARIABLE SOURCES_RESULT
        OUTPUT_VARIABLE SOURCES
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (NOT SOURCES_RESULT EQUAL 0)
        message(FATAL_ERROR "git ls-files [...]` returned ${SOURCES_RESULT}")
    endif()

    if(NOT "${SOURCES}" STREQUAL "")
        string(REPLACE "\n" ";" SOURCES ${SOURCES})
        list(TRANSFORM SOURCES PREPEND "${MICROV_SOURCE_ROOT_DIR}/")

        add_custom_command(TARGET clang-format
            COMMAND ${CMAKE_COMMAND} -E chdir ${MICROV_SOURCE_ROOT_DIR}
                    ${CLANG_FORMAT_BIN} --verbose -i ${SOURCES}
        )
    endif()

    add_custom_command(TARGET clang-format
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green "done"
    )
endif()