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
# Common functions.
###############################################################################
function text_common
{
	echo "      [>] Size of text."
	ls -l vmlinux vmlinux*.bin
	echo "      [>] Number of functions."
	cat vmlinux.asm | grep ">:" | wc -l
}

function systemcall_common
{
	echo "      [>] Count of 64bit system calls (prefix __x64)."
	cat vmlinux.asm | grep "<__x64" | wc -l
	echo "      [>] Count of 32bit system calls (prefix __ia32)."
	cat vmlinux.asm | grep "<__ia32" | wc -l
	echo "      [>] Count of system call candidate with call."
	cat 00.results/02.syscall_call.asm | grep "==>" | wc -l
	echo "      [>] Count of system call candidate with jump."
	cat 00.results/02.syscall_jump.asm | grep "==>" | wc -l
	echo "      [>] Make position raw data."
	cat 00.results/02.syscall_call.asm | grep "==>" > 00.results/02.syscall_position_raw.txt
	cat 00.results/02.syscall_jump.asm | grep "==>" >> 00.results/02.syscall_position_raw.txt
	echo "      [>] Extract aligned count."
	05.extract_branch_count.py 00.results/02.syscall_position_raw.txt > 00.results/02.syscall_position.txt
	cat 00.results/02.syscall_position.txt
}

function functioncall_common
{
	echo "      [>] Count of function call gadgets with call."
	cat 00.results/00.function_call_gadgets_call.asm | grep "==>" | wc -l
	echo "      [>] Count of function call gadgets with jump."
	cat 00.results/00.function_call_gadgets_jump.asm | grep "==>" | wc -l
	echo "      [>] Make position raw data."
	cat 00.results/00.function_call_gadgets_call.asm | grep "==>" > 00.results/00.function_call_gadget_position_raw.txt
	cat 00.results/00.function_call_gadgets_jump.asm | grep "==>" >> 00.results/00.function_call_gadget_position_raw.txt
	echo "      [>] Extract align information."
	05.extract_branch_count.py 00.results/00.function_call_gadget_position_raw.txt > 00.results/00.function_call_gadget_position.txt
	cat 00.results/00.function_call_gadget_position.txt
}

function functionnop_common
{
	echo "      [>] Count of function NOP gadgets. Aligned first and total."
	cat 00.results/01.function_nop_gadgets.asm | grep "==>" | grep "aligned 1" | wc -l
	cat 00.results/01.function_nop_gadgets.asm | grep "==>" | wc -l
}

function partialcall_common
{
	echo "      [>] Count of partial call gadgets with direct call. Aligned first and total."
	cat 00.results/03.partial_call_gadgets_call_direct.asm | grep "==>" | grep "aligned 1" | wc -l
	cat 00.results/03.partial_call_gadgets_call_direct.asm | grep "==>" | wc -l
	echo "      [>] Count of partial call gadgets with direct jump. Aligned first and total."
	cat 00.results/03.partial_call_gadgets_jump_direct.asm | grep "==>" | grep "aligned 1" | wc -l
	cat 00.results/03.partial_call_gadgets_jump_direct.asm | grep "==>" | wc -l
	echo "      [>] Count of partial call gadgets with indirect call Aligned first and total."
	cat 00.results/03.partial_call_gadgets_call_indirect.asm | grep "==>" | grep "aligned 1" | wc -l
	cat 00.results/03.partial_call_gadgets_call_indirect.asm | grep "==>" | wc -l
	echo "      [>] Count of partial call gadgets with indirect jump. Aligned first and total"
	cat 00.results/03.partial_call_gadgets_jump_indirect.asm | grep "==>" | grep "aligned 1" | wc -l
	cat 00.results/03.partial_call_gadgets_jump_indirect.asm | grep "==>" | wc -l
}

function partialnop_common
{
	echo "      [>] Count of partial NOP gadgets. Aligned first and total."
	cat 00.results/04.partial_nop_gadgets.asm | grep "==>" | grep "aligned 1" |  wc -l
	cat 00.results/04.partial_nop_gadgets.asm | grep "==>" | wc -l
}

function directcall_common
{
	echo "      [>] Extract position raw data from all direct call gadgets."
	cat 00.results/00.function_call_gadgets_call.asm | grep "==>" | grep "aligned 1" > 00.results/06.aligned_branch_position_raw.txt
	cat 00.results/00.function_call_gadgets_jump.asm | grep "==>" | grep "aligned 1" >> 00.results/06.aligned_branch_position_raw.txt
	cat 00.results/03.partial_call_gadgets_call_direct.asm | grep "==>" | grep "aligned 1" >> 00.results/06.aligned_branch_position_raw.txt
	cat 00.results/03.partial_call_gadgets_jump_direct.asm | grep "==>" | grep "aligned 1" >> 00.results/06.aligned_branch_position_raw.txt
	echo "      [>] Calculate position raw data."
	06.extract_aligned_branch_position.py 00.results/06.aligned_branch_position_raw.txt > 00.results/06.aligned_branch_position.txt

	echo "      [>] Print statistics raw data."
	06.extract_aligned_branch_position.py 00.results/06.aligned_branch_position_raw.txt 1
}

echo "Make reports..."
FAIL=0

###############################################################################
#  Text section size.
###############################################################################
echo "##############################"
echo "Show text section size"
echo "##############################"
echo "   ================================="
echo "   [*] Clang/LLVM CFI with Ubuntu..."
echo "   ================================="
cd KCFI_CET/kernel_disasm/ubuntu/
text_common

echo "   ================================="
echo "   [*] Clang/LLVM CFI with default..."
echo "   ================================="
cd ../
cd default
text_common

echo "   ================================="
echo "   [*] FineIBT with Ubuntu..."
echo "   ================================="
cd ../../../FineIBT/kernel_disasm/ubuntu
text_common

echo "   ================================="
echo "   [*] FineIBT with default..."
echo "   ================================="
cd ../
cd default
text_common

cd ../../../
echo ""

###############################################################################
# system call candidates.
###############################################################################
echo "##############################"
echo "Extract system call candidates"
echo "##############################"
echo "   ================================="
echo "   [*] Clang/LLVM CFI with Ubuntu..."
echo "   ================================="
cd KCFI_CET/kernel_disasm/ubuntu/
systemcall_common

echo "   ================================="
echo "   [*] Clang/LLVM CFI with default..."
echo "   ================================="
cd ../
cd default
systemcall_common

echo "   ================================="
echo "   [*] FineIBT with Ubuntu..."
echo "   ================================="
cd ../../../FineIBT/kernel_disasm/ubuntu
systemcall_common

echo "   ================================="
echo "   [*] FineIBT with default..."
echo "   ================================="
cd ../
cd default
systemcall_common
cd ../../../
echo ""

###############################################################################
# Function call gadgets.
###############################################################################
echo "##############################"
echo "Extract function call gadgets"
echo "##############################"
echo "   ================================="
echo "   [*] Clang/LLVM CFI with Ubuntu..."
echo "   ================================="
cd KCFI_CET/kernel_disasm/ubuntu/
functioncall_common

echo "   ================================="
echo "   [*] Clang/LLVM CFI with default..."
echo "   ================================="
cd ../
cd default
functioncall_common

echo "   ================================="
echo "   [*] FineIBT with Ubuntu..."
echo "   ================================="
cd ../../../FineIBT/kernel_disasm/ubuntu
functioncall_common

echo "   ================================="
echo "   [*] FineIBT with default..."
echo "   ================================="
cd ../
cd default
functioncall_common

cd ../../../
echo ""

###############################################################################
# Function NOP gadgets.
###############################################################################
echo "##############################"
echo "Extract function NOP gadgets"
echo "##############################"
echo "   ================================="
echo "   [*] Clang/LLVM CFI with Ubuntu..."
echo "   ================================="
cd KCFI_CET/kernel_disasm/ubuntu/
functionnop_common

echo "   ================================="
echo "   [*] Clang/LLVM CFI with default..."
echo "   ================================="
cd ../
cd default
functionnop_common

echo "   ================================="
echo "   [*] FineIBT with Ubuntu..."
echo "   ================================="
cd ../../../FineIBT/kernel_disasm/ubuntu
functionnop_common

echo "   ================================="
echo "   [*] FineIBT with default..."
echo "   ================================="
cd ../
cd default
functionnop_common

cd ../../../
echo ""


###############################################################################
# Partial call gadgets consisted of direct and indirect branches.
###############################################################################
echo "##############################"
echo "Extract partial call gadgets"
echo "##############################"
echo "   [*] Clang/LLVM CFI with Ubuntu..."
echo "   ================================="
cd KCFI_CET/kernel_disasm/ubuntu/
partialcall_common

echo "   [*] Clang/LLVM CFI with default..."
echo "   ================================="
cd ../
cd default
partialcall_common

echo "   [*] FineIBT with Ubuntu..."
echo "   ================================="
cd ../../../FineIBT/kernel_disasm/ubuntu
partialcall_common


echo "   [*] FineIBT with default..."
echo "   ================================="
cd ../
cd default
partialcall_common

cd ../../../
echo ""


###############################################################################
# Partial NOP gadgets.
###############################################################################
echo "##############################"
echo "Extract partial NOP gadgets"
echo "##############################"
echo "   [*] Clang/LLVM CFI with Ubuntu..."
echo "   ================================="
cd KCFI_CET/kernel_disasm/ubuntu/
partialnop_common

echo "   [*] Clang/LLVM CFI with default..."
echo "   ================================="
cd ../
cd default
partialnop_common

echo "   [*] FineIBT with Ubuntu..."
echo "   ================================="
cd ../../../FineIBT/kernel_disasm/ubuntu
partialnop_common

echo "   [*] FineIBT with default..."
echo "   ================================="
cd ../
cd default
partialnop_common

cd ../../../
echo ""

###############################################################################
# Direct call target addresses.
###############################################################################
echo "##############################"
echo "Extract direct call target"
echo "##############################"
echo "   [*] Clang/LLVM CFI with Ubuntu..."
echo "   ================================="
cd KCFI_CET/kernel_disasm/ubuntu/
directcall_common

echo "   [*] Clang/LLVM CFI with default..."
echo "   ================================="
cd ../
cd default
directcall_common

echo "   [*] FineIBT with Ubuntu..."
echo "   ================================="
cd ../../../FineIBT/kernel_disasm/ubuntu
directcall_common

echo "   [*] FineIBT with default..."
echo "   ================================="
cd ../
cd default
directcall_common

cd ../../../
echo ""

###############################################################################
# Create heatmaps.
###############################################################################
echo "##############################"
echo "Create Heatmaps"
echo "##############################"
gnuplot 00.scripts/07.draw_heatmap.gnuplot

###############################################################################
# Check if all jobs end.
###############################################################################
echo ""
echo "Wait for all processes..."
for job in `jobs -p`
do
echo $job
    wait $job
done
echo "   [*] Complete..."
