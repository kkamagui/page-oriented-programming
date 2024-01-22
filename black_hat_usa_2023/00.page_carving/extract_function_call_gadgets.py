#!/usr/bin/python3
import os
import sys


control_flow_change = ["jz", "jn", "je", "jg", "ja", "jb", "js", "jl", "jc", "jo", "int3", "ud2", "(bad)", "loop", "rep", "ret", "lret", "in", "out", "lcall", "ljmp",\
        "fist", "fst", "fwait", "wait", "fbld", "fbst", "fcmov", "fild", "fld", "fxch", "fabs", "\tfadd", "fch", "fdiv", "fiadd", "fidiv", "fimul", "fisub", "fmul", "fprem", "frndint", "fscale", "fsqrt", "fsub", "fxtract", "fcom", "ficom", "ftst", "fucom", "fxam", "f2xml", "fcos", "fpatan", "fptan", "fsin", "fyl2x", "fld", "fclex", "fdecstp", "ffree", "fincstp", "finit", "fnclex", "fninit", "fnop", "fnsave", "fnst", "frstor", "fsave", "fstcw", "fstenv", "fstsw"]
registers = ["%rax", "%eax", "%ax", "%rbx", "%ebx", "%bx", "%rcx", "%ecx", "%cx", "%rdx", "%edx", "%dx", "%rsi", "%esi", "%si", "%rdi", "%edi", "%di", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "%rbp", "%ebp", "%bp", "%rsp", "%esp", "%sp", "%rip", "%eip", "%ip"]

func_name = ""
function = 0
complete_function = 0
control_flow_changed = 0
func_addr = 0
detected = 0
call_used = 0
jump_used = 0
reg_used = 0
argument_modified = 0
call_target_addr = 0
call_pos_addr = 0
useful_function = 0
call_only_mode = 0
jump_only_mode = 0
function_length = 0
line_count = 0
line_data = ""
log_list = []

if (len(sys.argv) != 2):
    print("ex) script.py <jump_only = 0 or call_only = 1>")
    sys.exit(0)

# Set call or jmp mode.
if int(sys.argv[1]) == 1:
    print("   [*] call only mode...")
    call_only_mode = 1
    control_flow_change.append("\tjmp")
else:
    print("   [*] jmp only mode...")
    jump_only_mode = 1

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

# Get the call target address.
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

# Extract gadgets from a file.
asm_file = open('vmlinux.asm', 'r')

if asm_file == None:
    print("Please make vmlinux.asm file from the vmlinuz or vmlinux file")
    sys.exit(-1)

while True:
    # Get the next line from the file.
    line = asm_file.readline()
  
    prev_line_data = line_data 

    # if the line is empty, fill the line_data.
    if not line:
        line_data = ""
    else:
        line_data = line.strip()

    # Processing function.
    if ">:" in prev_line_data or not line:
        # Dump previous function.
        if len(log_list) > 1:
            for log in log_list:
                # Find all calls excluding system call candidates, and add them later.
                if "==> " in log and not ("__x64" in log or "__ia32" in log) and not "__cfi" in log:
                    function = 1

                #if "__x86_return_thunk" in log:
                if "\tret" in log:
                    complete_function = 1

                # Check if the target address of the call is in the same page. 
                if function == 1 and "==> " in log:
                    func_addr = get_func_addr(log)
                    continue

                ###########################################################
                # In the call case, function gadget's indirect calls are not usefull!
                ###########################################################
                if detected == 0 and function == 1 and \
                        ("\tcall " in log and not "__fentry__" in log):
                    detected = 1
                    call_used = 1
                    if not is_reg_included(log):
                        call_target_addr = get_call_target_addr(log)
                        call_pos_addr = get_call_pos_addr(log)
                        #print("func_addr %lX, call_target_addr %lX" % (func_addr, call_target_addr))
                    else:
                        reg_used = 1
                        break

                ###########################################################
                # In the jump case.
                ###########################################################
                if detected == 0 and function == 1 and \
                        ("\tjmp " in log and not "__x86_return_thunk" in log and not "_einittext" in log):
                    detected = 1
                    jump_used = 1
                    if not is_reg_included(log):
                        call_target_addr = get_call_target_addr(log)
                        call_pos_addr = get_call_pos_addr(log)
                    else:
                        reg_used = 1
                        break

                ###########################################################
                # Check if the function is useful.
                ###########################################################
                if detected == 1 and reg_used == 0 and \
                        abs(pa(func_addr) - pa(call_target_addr)) >= 4096 and \
                        abs(pa(call_pos_addr) - pa(call_target_addr)) >= 4096:

                    # Get the end address of the function.
                    if "..." in log_list[len(log_list) - 3]:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 4])
                    elif "Disassembly" in log_list[len(log_list) - 3]:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 6])
                    else:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 3])

                    # Check if call target address is not on the function's pages.
                    if abs(pa(func_last_addr) - pa(call_target_addr)) >= 4096 and \
                            (call_target_addr > func_last_addr or call_target_addr < func_addr):
                        # Check combination of flags.
                        if (jump_only_mode and jump_used) or (call_only_mode and call_used):
                            useful_function = 1

                ###########################################################
                # Check if control flows and arguemnts are changed.
                ###########################################################
                if detected == 0:
                    for asm in control_flow_change:
                        if asm in log:
                            control_flow_changed = 1
                            break

                    # Check RDI should not be changed.
                    if ",%edi" in log or ",%rdi" in log: # and not ("%rsi" in log or "%rdx" in log or "%rcx" in log or "%r8" in log or "%r9" in log):
                        argument_modified = 1
                        break

                if control_flow_changed == 1:
                    break

            ###########################################################
            # Dump function code
            ###########################################################
            if function == 1 and complete_function == 1 and detected == 1 and \
                    useful_function == 1 and control_flow_changed == 0 and argument_modified == 0:
                first = 0
                aligned = 0

                # gadget is aligned?
                if (func_addr & 0xf) == 0:
                    aligned = 1

                for log in log_list[:-1]:
                    if first == 0:
                        first = 1
                        print(log + " ,length %d , function %lx, call_pos %lx, call_target %lx, aligned %d, " % (line_count, func_addr, call_pos_addr, call_target_addr, aligned))
                        continue
                    print(log)

        log_list.clear()
        function = 0
        complete_function = 0
        detected = 0
        call_used = 0
        jump_used = 0
        reg_used = 0
        useful_function = 0
        control_flow_changed = 0
        argument_modified = 0
        function_length = 0
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
