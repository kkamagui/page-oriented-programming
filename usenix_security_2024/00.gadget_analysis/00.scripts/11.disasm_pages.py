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

# Example of extracting partial gadgets.
# $> objcopy -I elf64-little -j .text -O binary vmlinux vmlinux_text.bin
# $> objdump -b binary -m i386:x86-64 --start-address=0x00 --stop-address=0x1f -D vmlinux_text.bin | less

# Configuration blocks
#kernel_binary_name = "vmlinux_text.bin"    # Dump from the vmlinux file.
kernel_binary_name = "vmlinux_dump.bin"     # Dump from the kernel memory.
file_length = 0

file_stats = os.stat(kernel_binary_name)
file_length = file_stats.st_size

print("File size %d" % file_stats.st_size)

# For gadgets of the near 4 KB boundary, add some buffers.
# If you want to change parallelism, please change the step variable.
step = 32
for offset_in_page in range(0, 4096, step):
    # To leverage parallelism and reduce execution time, 31 threads are executed concurrently.
    # The last thread is executed sorely and waits to prevent resource exhaustion.
    for i in range(0, step - 1):
        os.system("12.disasm_page_offset.py %d &" % (offset_in_page + i))
    os.system("12.disasm_page_offset.py %d  " % (offset_in_page + (step - 1)))
