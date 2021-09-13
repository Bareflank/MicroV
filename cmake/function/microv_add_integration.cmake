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

# Add's An Integration Test Target
#
macro(microv_add_integration NAME HEADERS)
    add_executable(integration_${NAME})

    target_include_directories(integration_${NAME} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/../include/
        ${CMAKE_CURRENT_LIST_DIR}/support
    )

    if(HYPERVISOR_TARGET_ARCH STREQUAL "AuthenticAMD")
        target_include_directories(integration_${NAME} PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/support/x64
            ${CMAKE_CURRENT_LIST_DIR}/support/x64/amd
        )
    endif()

    if(HYPERVISOR_TARGET_ARCH STREQUAL "GenuineIntel")
        target_include_directories(integration_${NAME} PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/support/x64
            ${CMAKE_CURRENT_LIST_DIR}/support/x64/intel
        )
    endif()

    target_sources(integration_${NAME} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/${NAME}.cpp
    )

    target_compile_definitions(integration_${NAME} PRIVATE
        MICROV_MAX_VCPUS=${MICROV_MAX_VCPUS}_umx
        MICROV_MAX_PP_MAPS=${MICROV_MAX_PP_MAPS}_umx
    )

    target_compile_options(integration_${NAME} PRIVATE -Wframe-larger-than=4294967295)

    set_property(SOURCE ${NAME} APPEND PROPERTY OBJECT_DEPENDS ${${HEADERS}})

    target_link_libraries(integration_${NAME} PRIVATE
        bsl
        hypercall
        lib
        shim
    )

    if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR CMAKE_BUILD_TYPE STREQUAL MINSIZEREL)
        add_custom_command(TARGET integration_${NAME} POST_BUILD COMMAND ${CMAKE_STRIP} integration_${NAME})
    endif()

    install(TARGETS integration_${NAME} DESTINATION bin)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_custom_target(${NAME}
            COMMAND sync
            COMMAND ${CMAKE_BINARY_DIR}/integration_${NAME}
            VERBATIM
        )
    else()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
    endif()

    add_custom_command(TARGET run_all_integration_tests
        COMMAND ${CMAKE_COMMAND} --build . --target ${NAME}
        VERBATIM
    )
endmacro(microv_add_integration)
