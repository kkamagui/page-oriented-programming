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

# Create the data file.
os.system('cat vmlinux_static.asm | grep ">:" > vmlinux_functions_static.txt')

# Add function tags to the dump.asm file.
func_file = open("vmlinux_functions_static.txt", "r")
func_array = func_file.readlines()
func_file.close()

disasm_in_file = open("vmlinux_dump.asm", "r")

def find_function(disasm):
    match = 0
    ret = ""

    func_addr = (disasm.split(":"))[0]
    for function in func_array:
        if func_addr in function:
            match = 1
            break

    if match == 1:
        ret = function
        func_array.remove(function)

    return ret


while True:
    disasm = disasm_in_file.readline()

    # Exceptions 
    if not disasm:
        break
    if "file format binary" in disasm or "Disassembly of section .data" in disasm or "ffffffff81000000 <.data>" in disasm:
       continue 

    disasm = disasm.strip()
    if disasm == "":
        continue

    func_name = find_function(disasm)
    if func_name != "":
        print("")
        print(func_name.strip())
    
    print(disasm)
