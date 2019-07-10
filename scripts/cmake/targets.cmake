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

add_custom_target_category("MicroV Driver")

add_custom_target(builder_build
    COMMAND ${MICROV_SOURCE_UTIL_DIR}/driver_build.sh ${MICROV_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_build
    COMMENT "Build the microv driver"
)

add_custom_target(builder_clean
    COMMAND ${MICROV_SOURCE_UTIL_DIR}/driver_clean.sh ${MICROV_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_clean
    COMMENT "Clean the microv driver"
)

add_custom_target(builder_load
    COMMAND ${MICROV_SOURCE_UTIL_DIR}/driver_load.sh ${MICROV_SOURCE_ROOT_DIR}  ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_load
    COMMENT "Load the microv driver"
)

add_custom_target(builder_unload
    COMMAND ${MICROV_SOURCE_UTIL_DIR}/driver_unload.sh ${MICROV_SOURCE_ROOT_DIR} ${SOURCE_ROOT_DIR_NATIVE}
    USES_TERMINAL
)
add_custom_target_info(
    TARGET builder_unload
    COMMENT "Unload the microv driver"
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
add_dependencies(driver_quick builder_quick)

if(BUILD_XEN_GUEST)
    add_custom_target_category("MicroV Guest VM")

    execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${BR_BUILD_DIR})
    set(SRC ${MICROV_SOURCE_ROOT_DIR})

    configure_file(${SRC}/buildroot.config.in ${BR_BUILD_DIR}/.config @ONLY)
    configure_file(${SRC}/local.mk.in ${BR_BUILD_DIR}/local.mk @ONLY)

    add_custom_target(brmenucfg
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SOURCE_DIR} make O=${BR_BUILD_DIR} menuconfig
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET brmenucfg
        COMMENT "Configure the guest image with buildroot menuconfig"
    )
    add_custom_target(linuxrecfg
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SOURCE_DIR} make O=${BR_BUILD_DIR} linux-reconfigure
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET linuxrecfg
        COMMENT "Reconfigure the guest kernel"
    )
    add_custom_target(linuxrebuild
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SOURCE_DIR} make O=${BR_BUILD_DIR} linux-rebuild
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET linuxrebuild
        COMMENT "Rebuild the guest kernel"
    )
    add_custom_target(xenrebuild
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SOURCE_DIR} make O=${BR_BUILD_DIR} xen-rebuild
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET xenrebuild
        COMMENT "Rebuild the guest kernel"
    )
    add_custom_target(vm
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SOURCE_DIR} make O=${BR_BUILD_DIR}
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET vm
        COMMENT "Make the guest image"
    )

endif()
