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

not_allowed_inst = ["jz", "jn", "je", "jg", "ja", "jb", "js", "jl", "jc", "jo", "int3", "ud2", "(bad)", "enter", "leave", "push", "pop", "fldt", "loop", "rep", "ret", "lret", "in", "out", "rex", "%rip", "lcall", "ljmp", \
        "fist", "fst", "fwait", "wait", "fbld", "fbst", "fcmov", "fild", "fld", "fxch", "fabs", "\tfadd", "fch", "fdiv", "fiadd", "fidiv", "fimul", "fisub", "fmul", "fprem", "frndint", "fscale", "fsqrt", "fsub", "fxtract", "fcom", "ficom", "ftst", "fucom", "fxam", "f2xml", "fcos", "fpatan", "fptan", "fsin", "fyl2x", "fld", "fclex", "fdecstp", "ffree", "fincstp", "finit", "fnclex", "fninit", "fnop", "fnsave", "fnst", "frstor", "fsave", "fstcw", "fstenv", "fstsw"]
registers = ["%rax", "%eax", "%ax", "%rbx", "%ebx", "%bx", "%rcx", "%ecx", "%cx", "%rdx", "%edx", "%dx", "%rsi", "%esi", "%si", "%rdi", "%edi", "%di", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "%rbp", "%ebp", "%bp", "%rsp", "%esp", "%sp", "%rip", "%eip", "%ip"]

# 6 arguments can be used for syscalls.
indirect_registers = ["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"]
not_indirect_registers = ["%rsp", "%esp", "%rbp", "%ebp", "%rip", "%eip"]
call_only_mode = 0
jump_only_mode = 0
indirect_branch = 0

if (len(sys.argv) != 3):
    print("ex) script.py <jump_only = 0 or call_only = 1> <direct_only 0 or indirect_only 1>")
    sys.exit(0)

# Set call or jmp mode.
if int(sys.argv[1]) == 1:
    print("   [*] call only mode...")
    call_only_mode = 1
    not_allowed_inst.append("jmp")
else:
    print("   [*] jmp only mode...")
    jump_only_mode = 1

# Set indirect or direct mode.
if int(sys.argv[2]) == 1:
    print("   [*] indirect branch only mode...")
    indirect_branch = 1
else:
    print("   [*] direct branch only mode...")

# Get the page-aligned address.
def pa(addr):
    return addr & 0xfffffffffffff000

# Get the start address of a function.
def get_func_addr(log):
    column = log.split()
    func_addr = int(column[1], 16)
    return func_addr

# Get the address of a call or jump instruction.
def get_call_pos_addr(log):
    column = log.split(":")
    pos_addr = int(column[0], 16)
    return pos_addr

# Get the target address of a call or jump instruction.
def get_call_target_addr(log):
    call_target_addr = 0
    columns = log.split()
    found = 0
    for col in columns:
        if found == 1:
            call_target_addr = int(col, 16)
            break

        # Call or jump case
        if "call" in col or "jmp" in col:
            found = 1
            continue
       
    if found == 0:
        raise Exception("call page address error")

    return call_target_addr

# Check if registers are included.
def is_reg_included(log):
    for reg in registers:
        if reg in log:
            return True
    return False

# Check if the indirect branch is valid.
def is_indirect_branch(log):
    for reg in not_indirect_registers:
        if reg in log:
            return False

    for reg in indirect_registers:
        if reg in log:
            return True
    return False

# Extract gadgets from a file.
def extract_gadget(asm_file):
    func_name = ""
    not_allowed_inst_used = 0
    func_addr = 0
    detected = 0
    call_used = 0
    jump_used = 0
    reg_used = 0
    argument_modified = 0
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

        # if line is empty, fill the line_data.
        if not line:
            line_data = ""
        else:
            line_data = line.strip()

        # Processing function signatures.
        if ">:" in prev_line_data or not line:
            # Dump previous function
            if len(log_list) > 1:
                for log in log_list:
                    if "==>" in log:
                        func_addr = get_func_addr(log)
                        continue

                    ###########################################################
                    # In the call case, only the call instruction is allowed (not far call).
                    ###########################################################
                    if detected == 0 and "\tcall " in log:
                        detected = 1
                        call_used = 1
                        if indirect_branch == 0:
                            if not is_reg_included(log):
                                call_target_addr = get_call_target_addr(log)
                                call_pos_addr = get_call_pos_addr(log)
                                #print("func_addr %lX, call_target_addr %lX" % (func_addr, call_target_addr))
                            else:
                                reg_used = 1
                                break
                        else:
                            # In the case of indirect branch, no more check is needed.
                            if is_indirect_branch(log):
                                call_pos_addr = get_call_pos_addr(log)

                                # The mode should be matched.
                                if call_only_mode == 1:
                                    useful_function = 1
                            break

                    ###########################################################
                    # In the jump case, only the jump instruction is allowed.
                    ###########################################################
                    if detected == 0 and "\tjmp " in log:
                        detected = 1
                        jump_used = 1
                        if indirect_branch == 0:
                            if not is_reg_included(log):
                                call_target_addr = get_call_target_addr(log)
                                call_pos_addr = get_call_pos_addr(log)
                            else:
                                reg_used = 1
                                break
                        else:
                            # In the case of indirect branch, no more check is needed.
                            if is_indirect_branch(log):
                                call_pos_addr = get_call_pos_addr(log)

                                # The mode should be matched.
                                if jump_only_mode == 1:
                                    useful_function = 1
                            break

                    ###########################################################
                    # Check if the function is useful.
                    ###########################################################
                    if detected == 1 and reg_used == 0 and \
                            abs(pa(func_addr) - pa(call_target_addr)) >= 4096 and \
                            abs(pa(call_pos_addr) - pa(call_target_addr)) >= 4096:
                        if "..." in log_list[len(log_list) - 3]:
                            func_last_addr = get_call_pos_addr(log_list[len(log_list) - 4])
                        else:
                            func_last_addr = get_call_pos_addr(log_list[len(log_list) - 3])

                        if abs(pa(func_last_addr) - pa(call_target_addr)) >= 4096 and \
                                (call_target_addr > func_last_addr or call_target_addr < func_addr):
                            # Check mode
                            if (jump_only_mode and jump_used) or \
                                    (call_only_mode and call_used):
                                useful_function = 1
                        break

                    ###########################################################
                    # Check if control flows and arguments are changed.
                    ###########################################################
                    if detected == 0:
                        for asm in not_allowed_inst:
                            if asm in log:
                                not_allowed_inst_used = 1
                                break

                        # Check RDI if it is still controlled.
                        if ",%edi" in log or ",%rdi" in log: 
                            argument_modified = 1

                    if not_allowed_inst_used == 1:
                        break

                ###########################################################
                # Dump function code.
                ###########################################################
                if detected == 1 and useful_function == 1 and not_allowed_inst_used == 0 and argument_modified == 0: 
                    first = 0
                    aligned = 0
                    
                    # The gadget is aligned?
                    if (func_addr & 0xf) == 0:
                        aligned = 1

                    for log in log_list[:-1]:
                        if first == 0:
                            first = 1
                            print(log + " ,length %d , function %lx, call_pos %lx, call_target %lx, aligned %d, " % (line_count, func_addr, call_pos_addr, call_target_addr, aligned))
                            continue
                        print(log)

            log_list.clear()
            detected = 0
            call_used = 0
            jump_used = 0
            reg_used = 0
            useful_function = 0
            not_allowed_inst_used= 0
            argument_modified = 0
            function_length = 0
            line_count = 0
            func_name = "==> %s" % prev_line_data
            log_list.append(func_name)

        # If line is empty, the end of the file is reached.
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


