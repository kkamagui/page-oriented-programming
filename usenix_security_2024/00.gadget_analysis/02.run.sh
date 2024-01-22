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

function extract_data
{
	mkdir -p 00.results
	02.extract_syscall.py 1 > 00.results/02.syscall_call.asm &
	02.extract_syscall.py 0 > 00.results/02.syscall_jump.asm &
	00.extract_function_call_gadgets.py 1 > 00.results/00.function_call_gadgets_call.asm &
	00.extract_function_call_gadgets.py 0 > 00.results/00.function_call_gadgets_jump.asm &
	01.extract_function_nop_gadgets.py > 00.results/01.function_nop_gadgets.asm &
	03.extract_partial_call_gadgets.py 0 0 > 00.results/03.partial_call_gadgets_jump_direct.asm &
	03.extract_partial_call_gadgets.py 1 0 > 00.results/03.partial_call_gadgets_call_direct.asm &
	03.extract_partial_call_gadgets.py 0 1 > 00.results/03.partial_call_gadgets_jump_indirect.asm &
	03.extract_partial_call_gadgets.py 1 1 > 00.results/03.partial_call_gadgets_call_indirect.asm &
	04.extract_partial_nop_gadgets.py > 00.results/04.partial_nop_gadgets.asm &
}

echo "Make raw data..."
FAIL=0

echo "   [*] Clang/LLVM CFI with Ubuntu..."
cd KCFI_CET/kernel_disasm/ubuntu/
extract_data

echo "   [*] Clang/LLVM CFI with default..."
cd ../
cd default
extract_data

echo "   [*] FineIBT with Ubuntu..."
cd ../../../FineIBT/kernel_disasm/ubuntu
extract_data

echo "   [*] FineIBT with default..."
cd ../
cd default
extract_data

echo ""
echo "Wait for all processes..."
for job in `jobs -p`
do
echo $job
    wait $job
done
echo "   [*] Complete..."
