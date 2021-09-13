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

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/function/microv_add_integration.cmake)

list(APPEND HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/support/integration_utils.hpp
)

microv_add_integration(mv_debug_op_out HEADERS)
microv_add_integration(mv_handle_op_close_handle HEADERS)
microv_add_integration(mv_handle_op_open_handle HEADERS)
microv_add_integration(mv_hypercall_t HEADERS)
microv_add_integration(mv_vm_op_create_vm HEADERS)
microv_add_integration(mv_vm_op_destroy_vm HEADERS)
microv_add_integration(mv_vp_op_create_vp HEADERS)
microv_add_integration(mv_vp_op_destroy_vp HEADERS)
microv_add_integration(mv_vs_op_create_vs HEADERS)
microv_add_integration(mv_vs_op_destroy_vs HEADERS)
microv_add_integration(mv_vs_op_gla_to_gpa HEADERS)
