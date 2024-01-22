#!/bin/bash
#
#                   Page-Oriented Programming (POP)
#                   -------------------------------
#
#                   Copyright (C) 2023 Seunghun Han
#                 at the Affiliated Institute of ETRI
# Project link: https://github.com/kkamagui/page-oriented-programming 
#

echo "Add 00.scripts to the PATH env..."
SCRIPT_DIR="$(pwd)/00.scripts/"
export PATH=$SCRIPT_DIR:$PATH:

###############################################################################
# !!Caution!! 
# 	- The preparation process takes a lot of time!
#	- You need to prepare vmlinux and vmlinux_dump.bin file
###############################################################################
# Common function
function prepare_data
{
	xz -kd vmlinux.xz
	xz -kd vmlinux_dump.bin.xz

	objdump -d -j .text vmlinux 2>/dev/null > vmlinux_static.asm
	llvm-objdump -d -j .text vmlinux 2>/dev/null > vmlinux-llvm_static.asm
	objdump -b binary -m i386:x86-64 --adjust-vma=0xffffffff81000000 -D vmlinux_dump.bin 2>/dev/null > vmlinux_dump.asm
	objcopy -I elf64-little -j .text -O binary vmlinux vmlinux_text_static.bin
	10.add_function_info.py > vmlinux.asm &
}

echo "Make raw data..."
echo "   [*] Clang/LLVM CFI with Ubuntu..."
cd KCFI_CET/kernel_disasm/ubuntu/
prepare_data

echo "   [*] Clang/LLVM CFI with default..."
cd ../
cd default
prepare_data

echo "   [*] FineIBT with Ubuntu..."
cd ../../../FineIBT/kernel_disasm/ubuntu
prepare_data

echo "   [*] FineIBT with default..."
cd ../
cd default
prepare_data

echo ""
echo "Wait for all processes..."
for job in `jobs -p`
do
echo $job
    wait $job
done
echo "   [*] Complete..."
