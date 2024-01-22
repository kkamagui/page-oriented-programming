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

# Format file data.
for offset_in_page in range(0, 4096):
    output_file_name = "00.results/page_disasm_raw/page_disasm_%04X.asm" % offset_in_page
    print("   [*] %s" % output_file_name)

    file_asm = open(output_file_name, "r")
    line_data = file_asm.readlines()
    file_asm.close()

    file_asm = open(output_file_name, "w")
    for line in line_data:
        if "file format binary" in line:
            continue
        if "Disassembly of section" in line:
            continue
        if line == "\n":
            continue
       
        if ">:" in line:
            file_asm.write("\n")
        file_asm.write(line)

    file_asm.close()
