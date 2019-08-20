#!/usr/bin/python
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

import usb.core
import platform
import string
import time
import glob
import os

DBC_VEND = 0x1D6B
DBC_PROD = 0x0010
DBC_IFACE = 0x00
DBC_EP_IN = 0x81
DBC_EP_OUT = 0x01
DBC_READ_SIZE = 0x40

if platform.system() == 'Linux':
    raise ValueError('Linux is not implemented, use read.sh')

while 1:
    dbc = usb.core.find(idVendor=DBC_VEND, idProduct=DBC_PROD)
    if dbc is None:
        time.sleep(0.01)
    else:
        break

if platform.system() == 'Windows':
    dbc.set_configuration()
    while 1:
        try:
            data = dbc.read(DBC_EP_IN, DBC_READ_SIZE)
            for c in data:
                print(chr(c), end='')
        except usb.core.USBError:
            pass
