#!/bin/bash

find . | cpio -H newc -o | gzip > ../initrd.cpio.gz
