#!/usr/bin/python3
import os
import sys

control_flow_change = ["jz", "jn", "je", "jg", "ja", "jb", "js", "jl", "jc", "jo", "int3", "ud2", "(bad)", "loop", "rep", "ret", "lret", "in", "out", "lcall", "ljmp",\
        "fist", "fst", "fwait", "wait", "fbld", "fbst", "fcmov", "fild", "fld", "fxch", "fabs", "\tfadd", "fch", "fdiv", "fiadd", "fidiv", "fimul", "fisub", "fmul", "fprem", "frndint", "fscale", "fsqrt", "fsub", "fxtract", "fcom", "ficom", "ftst", "fucom", "fxam", "f2xml", "fcos", "fpatan", "fptan", "fsin", "fyl2x", "fld", "fclex", "fdecstp", "ffree", "fincstp", "finit", "fnclex", "fninit", "fnop", "fnsave", "fnst", "frstor", "fsave", "fstcw", "fstenv", "fstsw"]
registers = ["%rax", "%eax", "%ax", "%rbx", "%ebx", "%bx", "%rcx", "%ecx", "%cx", "%rdx", "%edx", "%dx", "%rsi", "%esi", "%si", "%rdi", "%edi", "%di", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "%rbp", "%ebp", "%bp", "%rsp", "%esp", "%sp", "%rip", "%eip", "%ip"]

func_name = ""
syscall = 0
control_flow_changed = 0
func_addr = 0
call_used = 0
reg_used = 0
argument_passed = 0
call_target_addr = 0
call_pos_addr = 0
useful_syscall = 0
call_only_mode = 0
jump_only_mode = 0
line_count = 0
line_data = ""
log_list = []

if (len(sys.argv) != 2):
    print("ex) script.py <call_only = 1 or jump_only = 0>")
    sys.exit(0)

# if call only mode
if int(sys.argv[1]) == 1:
    print("   [*] call only mode...")
    call_only_mode = 1
    control_flow_change.append("jmp")
else:
    print("   [*] jmp only mode...")
    jump_only_mode = 1

# Get page-aligned addr
def pa(addr):
    return addr & 0xfffffffffffff000

# Get start page address of function
def get_func_page_addr(log):
    column = log.split()
    func_addr = int(column[1], 16)
    #return func_addr & 0xfffffffffffff000
    return func_addr

# Get start page address of function
def get_call_pos_page_addr(log):
    column = log.split(":")
    pos_addr = int(column[0], 16)
    #return pos_addr & 0xfffffffffffff000
    return pos_addr

# Get call target address
def get_call_target_page_addr(log):
    call_addr = 0
    columns = log.split()
    found = 0
    for col in columns:
        if found == 1:
            call_addr = int(col, 16)
            break

        # call and jump case
        if "call" in col or "jmp" in col:
            found = 1
            continue
       
    if found == 0:
        raise Exception("call page address error")

    #return call_addr & 0xfffffffffffff000
    return call_addr

# Check if registers are included.
def is_reg_included(log):
    for reg in registers:
        if reg in log:
            return True
    return False

# Using readline()
asm_file = open('vmlinux.asm', 'r')
if asm_file == None:
    print("Please make vmlinux.asm file from the vmlinuz or vmlinux file")
    sys.exit(-1)

while True:
    # Get next line from file
    line = asm_file.readline()

    prev_line_data = line_data

    # if line is empty
    if not line:
        line_data = ""
    else:
        line_data = line.strip()

    if ">:" in prev_line_data or not line:
        # Dump previous function
        if len(log_list) > 1:
            for log in log_list:
                # Find syscall
                if "==> " in log and ("__x64" in log or "__ia32" in log) and not "__cfi" in log:
                    syscall = 1

                # Check a target address of the call is in the same page. 
                if syscall == 1 and "==> " in log:
                    func_addr = get_func_page_addr(log)
                    continue

                ###########################################################
                # Call case
                ###########################################################
                if call_used == 0 and syscall == 1 and (call_only_mode == 1 and "call " in log and not "__fentry__" in log):
                    call_used = 1
                    if not is_reg_included(log):
                        call_target_addr = get_call_target_page_addr(log)
                        call_pos_addr = get_call_pos_page_addr(log)
                    else:
                        reg_used = 1
                        break

                ###########################################################
                # Jump case
                ###########################################################
                if call_used == 0 and syscall == 1 and (jump_only_mode == 1 and "jmp " in log and not "__x86_return_thunk" in log):
                    call_used = 1
                    if not is_reg_included(log):
                        call_target_addr = get_call_target_page_addr(log)
                        call_pos_addr = get_call_pos_page_addr(log)
                    else:
                        reg_used = 1
                        break

                ###########################################################
                # Check if the function is useful
                ###########################################################
                if useful_syscall == 0 and call_used == 1 and reg_used == 0 and abs(pa(func_addr) - pa(call_target_addr)) >= 4096 and abs(pa(call_pos_addr) - pa(call_target_addr)) >= 4096:
                    if "..." in log_list[len(log_list) - 3]:
                        func_last_addr = get_call_pos_page_addr(log_list[len(log_list) - 4])
                    elif "Disassembly" in log_list[len(log_list) - 3]:
                        func_last_addr = get_call_pos_page_addr(log_list[len(log_list) - 6])
                    else:
                        func_last_addr = get_call_pos_page_addr(log_list[len(log_list) - 3])

                    # call target address should not be in the function
                    if abs(pa(func_last_addr) - pa(call_target_addr)) >= 4096 and (call_target_addr > func_last_addr or call_target_addr < func_addr):
                        useful_syscall = 1
                        break

                ###########################################################
                # Check if control-flow changes and arguemnt passed
                ###########################################################
                if call_used == 0:
                    for asm in control_flow_change:
                        if asm in log:
                            control_flow_changed = 1
                            break

                    # Check RDI, RSI is assigned before call and not local or pcpu_hot data
                    #if (",%edi" in log or ",%rdi" in log) and (",%esi" in log or ",%rsi" in log) and \
                    #        not ("rbp" in log or "pcpu_hot" in log):
                    # Check RDI is assigned before call and not local or pcpu_hot data
                    if (",%edi" in log or ",%rdi" in log):# and not ("%rbp" in log or "%rsp" in log or "%gs" in log):
                        if (not ("%rbp" in log or "%rsp" in log or "%gs" in log or "xor" in log or "0x" in log)) or \
                                ("0x" in log and "(%rdi)," in log):
                            argument_passed = 1
                        else:
                            argument_passed = 0

                if control_flow_changed == 1:
                    break

            """
            # Too hard rule!!
            # Check if the last page of the function
            if syscall == 1 and useful_syscall == 1:
                print("Last of the function " + log_list[len(log_list) - 3])
                func_end = log_list[len(log_list) - 3].split(":")
                func_end = int(func_end[0], 16)
                print("Last of the function %lx" % func_end)
            """

            ###########################################################
            # Dump function code
            ###########################################################
            #if rip_or_call_used == 0 and start_with_endbr == 1 and end_with_ret == 1:
            if syscall == 1 and call_used == 1 and useful_syscall == 1 and argument_passed == 1 and control_flow_changed == 0:
                first = 0
                for log in log_list[:-1]:
                    if first == 0:
                        first = 1
                        print(log + " ,length %d , function %lx, call_pos %lx, call_target %lx, " % (line_count, func_addr, call_pos_addr, call_target_addr))
                        continue

                    print(log)

        log_list.clear()
        syscall = 0
        call_used = 0
        reg_used = 0
        useful_syscall = 0
        control_flow_changed = 0
        argument_passed = 0
        line_count = 0
        func_name = "==> %s" % prev_line_data
        log_list.append(func_name)

    # if line is empty
    # end of file is reached
    if not line:
        break

    # function logging
    log_list.append(line_data)

# Function line count. Don't count meaninigless instructions.
    temp = line_data.split("\t")
    if len(temp) > 2 and not "nop" in temp[2] and not "int3" in temp[2] and not "nopl" in temp[2] and not "nopw" in temp[2] and not "ud2" in temp[2]:
        line_count = line_count + 1

asm_file.close()
