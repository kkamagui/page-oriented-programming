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
#	- You need to execute the 00.prepare.sh file first. 
###############################################################################
# Common function
function disassem_data
{
	11.disasm_pages.py &
}

function format_data
{
	13.format_page_disasm.py &
}

echo "Disassemble each page offset..."
echo "   [*] Clang/LLVM CFI with Ubuntu..."
cd KCFI_CET/kernel_disasm/ubuntu/
disassem_data

echo "   [*] Clang/LLVM CFI with default..."
cd ../
cd default
disassem_data

echo "   [*] FineIBT with Ubuntu..."
cd ../../../FineIBT/kernel_disasm/ubuntu
disassem_data

echo "   [*] FineIBT with default..."
cd ../
cd default
disassem_data

echo "Wait for disassembly processes..."
for job in `jobs -p`
do
echo $job
    wait $job
done
echo "   [*] Complete..."


echo "Format data..."
echo "   [*] Clang/LLVM CFI with Ubuntu..."
cd ../../../KCFI_CET/kernel_disasm/ubuntu/
format_data

echo "   [*] Clang/LLVM CFI with default..."
cd ../
cd default
format_data

echo "   [*] FineIBT with Ubuntu..."
cd ../../../FineIBT/kernel_disasm/ubuntu
format_data

echo "   [*] FineIBT with default..."
cd ../
cd default
format_data

echo "Wait for disassembly processes..."
for job in `jobs -p`
do
echo $job
    wait $job
done
echo "   [*] Complete..."
