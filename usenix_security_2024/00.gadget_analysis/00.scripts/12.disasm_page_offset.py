#!/usr/bin/python3
#
#                   Page-Oriented Programming (POP)
#                   -------------------------------
#
#                   Copyright (C) 2023 Seunghun Han
#                 at the Affiliated Institute of ETRI
# Project link: https://github.com/kkamagui/page-oriented-programming 
#
import os
import sys

# Example of extracting partial gadgets.
# $> objcopy -I elf64-little -j .text -O binary vmlinux vmlinux_text.bin
# $> objdump -b binary -m i386:x86-64 --start-address=0x1e0 --stop-address=0x1ff -D vmlinux_text.bin | less

# Configuration blocks
#kernel_binary_name = "vmlinux_text.bin"    # Dump from the vmlinux file.
kernel_binary_name = "vmlinux_dump.bin"     # Dump from the kernel memory.
file_length = 0
disasm_size = 32
offset_in_page = int(sys.argv[1])

print("Offset is %04X" % offset_in_page)

file_stats = os.stat(kernel_binary_name)
file_length = file_stats.st_size

print("File size %d" % file_stats.st_size)

os.system("mkdir -p 00.results/page_disasm_raw")
output_file_name = "00.results/page_disasm_raw/page_disasm_%04X.asm" % offset_in_page
os.system("rm %s" % output_file_name)

print("================= %X =================" % offset_in_page)
# Jump pages and disassemble at the offset
for i in range(0, file_length, 0x1000):
    if (i % 1000) == 0:
        print("[%X/%X] disassembling..." % (i + offset_in_page, file_length))
    os.system("objdump -b binary -m i386:x86-64 --start-address=%d --stop-address=%d -D %s >> %s" % (i + offset_in_page, i+ offset_in_page + disasm_size, kernel_binary_name, output_file_name))
