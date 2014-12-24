#!/bin/bash

ld -melf_x86_64 -nostdlib 
gcc ./src/test.c -o test -I ../../include -I -O2 -Wall -m64 -ffreestanding -std=gnu99 -Werror -D_GW1_ -D_PACKETVIEWER_  -L ../../lib/libpacketngin.a -L ../../lib/libcrypto.a -L ../../lib/libssl.a 

 
