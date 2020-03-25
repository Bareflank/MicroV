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

# ------------------------------------------------------------------------------
# Driver
# ------------------------------------------------------------------------------

if(WIN32)
    return()
endif()

file(TO_NATIVE_PATH "${SOURCE_ROOT_DIR}" SOURCE_ROOT_DIR_NATIVE)

add_custom_target_category("Boxy Driver")

add_custom_target(builder_build
    COMMAND ${BOXY_SOURCE_UTIL_DIR}/driver_build.sh ${BOXY_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_build
    COMMENT "Build the boxy driver"
)

add_custom_target(builder_clean
    COMMAND ${BOXY_SOURCE_UTIL_DIR}/driver_clean.sh ${BOXY_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_clean
    COMMENT "Clean the boxy driver"
)

add_custom_target(builder_load
    COMMAND ${BOXY_SOURCE_UTIL_DIR}/driver_load.sh ${BOXY_SOURCE_ROOT_DIR}  ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_load
    COMMENT "Load the boxy driver"
)

add_custom_target(builder_unload
    COMMAND ${BOXY_SOURCE_UTIL_DIR}/driver_unload.sh ${BOXY_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_unload
    COMMENT "Unload the boxy driver"
)

add_custom_target(
    builder_quick
    COMMAND ${CMAKE_COMMAND} --build . --target builder_unload
    COMMAND ${CMAKE_COMMAND} --build . --target builder_clean
    COMMAND ${CMAKE_COMMAND} --build . --target builder_build
    COMMAND ${CMAKE_COMMAND} --build . --target builder_load
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_quick
    COMMENT "Unload, clean, build, and load the Bareflank driver"
)

add_dependencies(driver_build builder_build)
add_dependencies(driver_clean builder_clean)
add_dependencies(driver_load builder_load)
add_dependencies(driver_unload builder_unload)
