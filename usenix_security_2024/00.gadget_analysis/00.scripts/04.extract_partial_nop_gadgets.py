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

# Pop and leave are only allowed in contrast to the partial gadget extractor.
not_allowed_inst = ["jz", "jn", "je", "jg", "ja", "jb", "js", "jl", "jc", "jo", "int3", "ud2", "(bad)", "enter", "push", "fldt", "loop", "rep", "lret", "in", "out", "rex", "%rip", "lcall", "ljmp", \
        "fist", "fst", "fwait", "wait", "fbld", "fbst", "fcmov", "fild", "fld", "fxch", "fabs", "\tfadd", "fch", "fdiv", "fiadd", "fidiv", "fimul", "fisub", "fmul", "fprem", "frndint", "fscale", "fsqrt", "fsub", "fxtract", "fcom", "ficom", "ftst", "fucom", "fxam", "f2xml", "fcos", "fpatan", "fptan", "fsin", "fyl2x", "fld", "fclex", "fdecstp", "ffree", "fincstp", "finit", "fnclex", "fninit", "fnop", "fnsave", "fnst", "frstor", "fsave", "fstcw", "fstenv", "fstsw"]

# Get the page-aligned address.
def pa(addr):
    return addr & 0xfffffffffffff000

# Get the start address of a function.
def get_func_addr(log):
    column = log.split()
    func_addr = int(column[1], 16)
    return func_addr

# Extract gadgets from a file.
def extract_gadget(asm_file):
    func_name = ""
    not_allowed_inst_used = 0
    func_addr = 0
    detected = 0
    call_used = 0
    jump_used = 0
    reg_used = 0
    call_target_addr = 0
    call_pos_addr = 0
    useful_function = 0
    function_length = 0
    line_count = 0
    line_data = ""
    log_list = []

    while True:
        # Get the next line from the file.
        line = asm_file.readline()
      
        prev_line_data = line_data 

        # if the line is empty, fill the line_data.
        if not line:
            line_data = ""
        else:
            line_data = line.strip()

        # Processing function signatures. 
        if ">:" in prev_line_data or not line:
            # Dump previous function.
            if len(log_list) > 1:
                for log in log_list:
                    if "==>" in log:
                        func_addr = get_func_addr(log)
                        continue

                    ###########################################################
                    # In the call case, NOP gadgets should not call other functions.
                    ###########################################################
                    if "call" in log:
                        call_used = 1
                        break

                    ###########################################################
                    # In the jump case, NOP gadgets should not jump to other locations.
                    ###########################################################
                    if "jmp" in log:
                        jump_used = 1
                        break

                    if "\tret" in log:
                        detected = 1
                        useful_function = 1
                        break

                    ###########################################################
                    # Check if control flows are changed.
                    ###########################################################
                    if detected == 0:
                        for asm in not_allowed_inst:
                            if asm in log:
                                not_allowed_inst_used = 1
                                break

                    if not_allowed_inst_used == 1:
                        break

                ###########################################################
                # Dump function code.
                ###########################################################
                if useful_function == 1 and not_allowed_inst_used == 0 and call_used == 0 and jump_used == 0:
                    first = 0
                    aligned = 0
                    
                    # The gadget is aligned?
                    if (func_addr & 0xf) == 0:
                        aligned = 1

                    for log in log_list[:-1]:
                        if first == 0:
                            first = 1
                            print(log + " ,length %d , function %lx, aligned %d, " % (line_count, func_addr, aligned))
                            continue
                        print(log)

            log_list.clear()
            detected = 0
            call_used = 0
            jump_used = 0
            reg_used = 0
            useful_function = 0
            not_allowed_inst_used= 0
            function_length = 0
            line_count = 0
            func_name = "==> %s" % prev_line_data
            log_list.append(func_name)

        # If the line is empty, the end of the file is reached.
        if not line:
            break

        # Accumulate function code.
        log_list.append(line_data)

        # Count function lines. Don't count meaningless instructions.
        temp = line_data.split("\t")
        if len(temp) > 2 and not "nop" in temp[2] and not "int3" in temp[2] and not "nopl" in temp[2] and not "nopw" in temp[2] and not "ud2" in temp[2]:
            line_count = line_count + 1

def main():
    # Extract all gadgets from offset 0 to 4095.
    for i in range(0, 4096):
        asm_file = open('00.results/page_disasm_raw/page_disasm_%04X.asm' % i, 'r')
       
        # Extract gadgets.
        extract_gadget(asm_file)

        asm_file.close()


if __name__ == "__main__":
    main()
