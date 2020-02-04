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

if(WIN32)
    return()
endif()

file(TO_NATIVE_PATH "${SOURCE_ROOT_DIR}" SOURCE_ROOT_DIR_NATIVE)

# ------------------------------------------------------------------------------
# Drivers
# ------------------------------------------------------------------------------

function(add_driver_targets DRV)
    set(SH_DIR ${MICROV_SOURCE_UTIL_DIR})
    set(MV_SRC ${MICROV_SOURCE_ROOT_DIR})
    set(BF_SRC ${SOURCE_ROOT_DIR_NATIVE})

    add_custom_target(${DRV}_build
        COMMAND ${SH_DIR}/driver_build.sh ${MV_SRC} ${BF_SRC} ${DRV}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${DRV}_build
        COMMENT "Build the ${DRV} driver"
    )

    add_custom_target(${DRV}_clean
        COMMAND ${SH_DIR}/driver_clean.sh ${MV_SRC} ${DRV}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${DRV}_clean
        COMMENT "Clean the ${DRV} driver"
    )

    add_custom_target(${DRV}_load
        COMMAND ${SH_DIR}/driver_load.sh ${MV_SRC} ${DRV}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${DRV}_load
        COMMENT "Load the ${DRV} driver"
    )

    add_custom_target(${DRV}_unload
        COMMAND ${SH_DIR}/driver_unload.sh ${MV_SRC} ${DRV}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${DRV}_unload
        COMMENT "Unload the ${DRV} driver"
    )

    add_custom_target(
        ${DRV}_quick
        COMMAND ${CMAKE_COMMAND} --build . --target ${DRV}_unload
        COMMAND ${CMAKE_COMMAND} --build . --target ${DRV}_clean
        COMMAND ${CMAKE_COMMAND} --build . --target ${DRV}_build
        COMMAND ${CMAKE_COMMAND} --build . --target ${DRV}_load
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${DRV}_quick
        COMMENT "Unload, clean, build, and load the ${DRV} driver"
    )

    add_dependencies(driver_unload ${DRV}_unload)
    add_dependencies(driver_clean ${DRV}_clean)
    add_dependencies(driver_build ${DRV}_build)
    add_dependencies(driver_load ${DRV}_load)
    add_dependencies(driver_quick ${DRV}_quick)
endfunction(add_driver_targets)

if(BUILD_BUILDER OR BUILD_VISR)
    add_custom_target_category("MicroV Drivers")
endif()

if(BUILD_BUILDER)
    add_driver_targets(builder)
endif()

if(BUILD_VISR)
    add_driver_targets(visr)
endif()
