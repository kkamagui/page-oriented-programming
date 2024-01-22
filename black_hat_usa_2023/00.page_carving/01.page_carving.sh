#!/bin/bash

echo "Page carving starts ..."

echo "   [*] Disassembling the vmlinux file"
objdump -d vmlinux > vmlinux.asm 2>/dev/null
echo "       ==> Complete"

echo "   [*] Extracting system call candidates"
./extract_syscalls.py 1 > 00.results/syscalls.asm
echo "       ==> Complete"

echo "   [*] Extracting call gadgets"
./extract_function_call_gadgets.py 1 > 00.results/call_gadgets.asm
echo "       ==> Complete"

echo "   [*] Extracting NOP gadgets"
./extract_function_nop_gadgets.py > 00.results/nop_gadgets.asm
echo "       ==> Complete"

