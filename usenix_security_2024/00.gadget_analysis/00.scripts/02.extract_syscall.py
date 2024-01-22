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
rdi_changed = 0
rsp_alias = ""
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

# Set call or jump mode.
if int(sys.argv[1]) == 1:
    print("   [*] call only mode...")
    call_only_mode = 1
    control_flow_change.append("jmp")
else:
    print("   [*] jmp only mode...")
    jump_only_mode = 1

# Get the page-aligned address.
def pa(addr):
    return addr & 0xfffffffffffff000

# Get the start address of a function
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
    call_addr = 0
    columns = log.split()
    found = 0
    for col in columns:
        if found == 1:
            call_addr = int(col, 16)
            break

        # Call or jump case
        if "call" in col or "jmp" in col:
            found = 1
            continue
       
    if found == 0:
        raise Exception("call page address error")

    return call_addr

# Get alias of RSP.
def get_rsp_alias(log, org_alias):
    call_addr = 0
    found = 0
    reg_part = ""
    rsp_alias = ""

    columns = log.split()

    for col in columns:
        if found == 1:
            reg_part = col
            break

        if "%rsp," in col or "%rsp)," in col:
            found = 1
            continue

    if found == 1:
        regs = log.split(",")
        if is_reg_included(regs[1]) == True:
            rsp_alias = regs[1]
            #print("============> %s, %s" % (rsp_alias, log))
    else:
        return org_alias

    return rsp_alias


# Check if registers are included.
def is_reg_included(log):
    for reg in registers:
        if reg in log:
            return True
    return False

# Extract gadgets from a file.
asm_file = open('vmlinux.asm', 'r')

while True:
    # Get the next line from the file.
    line = asm_file.readline()

    prev_line_data = line_data

    # if line is empty, fill the line_data.
    if not line:
        line_data = ""
    else:
        line_data = line.strip()

    if ">:" in prev_line_data or not line:
        # Dump previous function.
        if len(log_list) > 1:
            for log in log_list:
                # Find syscalls.
                if "==> " in log and ("__x64" in log or "__ia32" in log) and not "__cfi" in log:
                    syscall = 1
                    #print(log)

                # Check the target address of the call is in the same page. 
                if syscall == 1 and "==> " in log:
                    func_addr = get_func_addr(log)
                    continue

                ###########################################################
                # In the call case.
                ###########################################################
                if call_used == 0 and syscall == 1 and (call_only_mode == 1 and "call " in log and not "__fentry__" in log):
                    call_used = 1
                    if not is_reg_included(log):
                        call_target_addr = get_call_target_addr(log)
                        call_pos_addr = get_call_pos_addr(log)
                    else:
                        reg_used = 1
                        break

                ###########################################################
                # In the jump case.
                ###########################################################
                if call_used == 0 and syscall == 1 and (jump_only_mode == 1 and "jmp " in log and not "__x86_return_thunk" in log):
                    call_used = 1
                    if not is_reg_included(log):
                        call_target_addr = get_call_target_addr(log)
                        call_pos_addr = get_call_pos_addr(log)
                    else:
                        reg_used = 1
                        break

                ###########################################################
                # Check if the function is useful.
                ###########################################################
                if useful_syscall == 0 and call_used == 1 and reg_used == 0 and abs(pa(func_addr) - pa(call_target_addr)) >= 4096 and abs(pa(call_pos_addr) - pa(call_target_addr)) >= 4096:
                    if "..." in log_list[len(log_list) - 3]:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 4])
                    elif "Disassembly" in log_list[len(log_list) - 3]:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 6])
                    else:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 3])

                    # The call target address should not be in the function.
                    if abs(pa(func_last_addr) - pa(call_target_addr)) >= 4096 and (call_target_addr > func_last_addr or call_target_addr < func_addr):
                        useful_syscall = 1
                        break

                ###########################################################
                # Check RSP alias
                ###########################################################
                rsp_alias = get_rsp_alias(log, rsp_alias)

                ###########################################################
                # Check if control flows and arguments are changed.
                ###########################################################
                if call_used == 0:
                    for asm in control_flow_change:
                        if asm in log:
                            control_flow_changed = 1
                            break

                    # Check RDI is assigned before call and not from the local or pcpu_hot data
                    if (",%edi" in log or ",%rdi" in log) and rdi_changed == 0:
                        # If call this twice, rdi is changed.
                        #if argument_passed == 1:
                        #    rdi_changed = 1
                        #    #print("==> RDI assigned again, %s" % (log))
                        #    break
                        if (not ("%rbp" in log or "%rsp" in log or "%gs" in log or "xor" in log or "0x" in log or (rsp_alias != "" and rsp_alias in log))) or \
                                ("0x" in log and "(%rdi)," in log):
                            argument_passed = 1
                            #print("==> Argument passed, %s, rsp alias %s" % (log, rsp_alias))
                        else:
                            argument_passed = 0
                            #rdi_changed = 1
                            #print("==> RDI changed, rsp alias [%s], %s" % (rsp_alias, log))
                            #break

                if control_flow_changed == 1:
                    break

            ###########################################################
            # Dump function code.
            ###########################################################
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
        rdi_changed = 0
        rsp_alias = ""
        line_count = 0
        func_name = "==> %s" % prev_line_data
        log_list.append(func_name)

    # if the line is empty, the end of the file is reached.
    if not line:
        break

    # Accumulate function code.
    log_list.append(line_data)

    # Count function lines. Don't count meaningless instructions.
    temp = line_data.split("\t")
    if len(temp) > 2 and not "nop" in temp[2] and not "int3" in temp[2] and not "nopl" in temp[2] and not "nopw" in temp[2] and not "ud2" in temp[2]:
        line_count = line_count + 1

asm_file.close()
