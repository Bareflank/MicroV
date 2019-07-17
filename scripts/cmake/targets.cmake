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

# ------------------------------------------------------------------------------
# Guest VMs
# ------------------------------------------------------------------------------

function(add_vm_targets VM)
    set(BR_BIN ${BR_BIN_DIR}/${VM})
    set(BR_CFG ${BR_SRC_DIR}/configs)
    set(MV_SRC ${MICROV_SOURCE_ROOT_DIR})

    execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${BR_BIN})
    configure_file(${MV_SRC}/local.mk.in ${BR_BIN}/local.mk @ONLY)
    configure_file(${BR_CFG}/venom_${VM}_config.in ${BR_BIN}/.config @ONLY)

    add_custom_target(${VM}
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN}
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}
        COMMENT "Make the ${VM} image"
    )

    add_custom_target(${VM}-clean
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} clean
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-clean
        COMMENT "Clean the ${VM} image"
    )

    add_custom_target(${VM}-distclean
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} distclean
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-distclean
        COMMENT "Clean the ${VM} image, including .config"
    )

    add_custom_target(${VM}-cfg
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} menuconfig
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-cfg
        COMMENT "Configure the ${VM} with buildroot"
    )

    add_custom_target(${VM}-linux-cfg
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} linux-menuconfig
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} linux-update-defconfig
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-linux-cfg
        COMMENT "Configure the ${VM} kernel"
    )

    add_custom_target(${VM}-linux-recfg
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} linux-reconfigure
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-linux-recfg
        COMMENT "Restart the ${VM} kernel build from the configure step"
    )

    add_custom_target(${VM}-linux-rebuild
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} linux-rebuild
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-linux-rebuild
        COMMENT "Restart the ${VM} kernel build from the build step"
    )


if(GRAPH_GUEST_IMAGES)
    add_custom_target(${VM}-graph-size
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} graph-size
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-graph-size
        COMMENT "Graph the ${VM} filesystem size"
    )

    add_custom_target(${VM}-graph-depends
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} graph-depends
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-graph-depends
        COMMENT "Graph the ${VM} filesystem dependencies"
    )

    add_custom_target(${VM}-graph-build
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN} graph-build
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET ${VM}-graph-build
        COMMENT "Graph the ${VM} package build times"
    )
endif()

# Add xenstore VM targets
if(VM STREQUAL xsvm)
    add_custom_target(xsvm-xen-recfg
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN_DIR} xen-reconfigure
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET xsvm-xen-recfg
        COMMENT "Reconfigure xen tools"
    )
    add_custom_target(xsvm-xen-rebuild
        COMMAND ${CMAKE_COMMAND} -E chdir ${BR_SRC_DIR} make O=${BR_BIN_DIR} xen-rebuild
        DEPENDS xtools_x86_64-userspace-elf
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET xsvm-xen-rebuild
        COMMENT "Rebuild xen tools"
    )
endif()

endfunction(add_vm_targets)

if(BUILD_XEN_GUEST)
    add_custom_target_category("MicroV Guest VMs")

    add_vm_targets(vm)
    add_vm_targets(xsvm)
    add_vm_targets(ndvm)
endif()
