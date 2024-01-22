#!/usr/bin/python3
import os
import sys

registers = ["%rax", "%eax", "%ax", "%rbx", "%ebx", "%bx", "%rcx", "%ecx", "%cx", "%rdx", "%edx", "%dx", "%rsi", "%esi", "%si", "%rdi", "%edi", "%di", "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "%rbp", "%ebp", "%bp", "%rsp", "%esp", "%sp", "%rip", "%eip", "%ip"]

func_name = ""
function = 0
complete_function = 0
func_addr = 0
call_used = 0
reg_used = 0
call_target_addr = 0
call_pos_addr = 0
unuseful_function = 0
call_only_mode = 0
jump_only_mode = 0
function_length = 0
line_count = 0
line_data = ""
log_list = []

# Get the page-aligned address.
def pa(addr):
    return addr & 0xfffffffffffff000

# Get the start address of a function.
def get_func_addr(log):
    column = log.split()
    func_addr = int(column[1], 16)
    return func_addr

# Get the start page address of a function.
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

        # Call and jump case
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
        # Dump previous function
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

                # In the call case.
                if function == 1 and ("call " in log and not "__fentry__" in log):
                    unuseful_function = 1
                    break

                # In the jump case, indirect call is useless for nop.
                if function == 1 and ("jmp " in log and not "__x86_return_thunk" in log):
                    call_used = 1
                    if not is_reg_included(log):
                        call_target_addr = get_call_target_addr(log)
                        call_pos_addr = get_call_pos_addr(log)
                    else:
                        reg_used = 1
                        unuseful_function = 1
                        break

                ###########################################################
                # Check if the function is useful.
                ###########################################################
                if call_used == 1 and reg_used == 0 and unuseful_function == 0 and abs(pa(func_addr) - pa(call_target_addr)) >= 4096 and abs(pa(call_pos_addr) - pa(call_target_addr)) >= 4096:
                    if "..." in log_list[len(log_list) - 3]:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 4])
                    elif "Disassembly" in log_list[len(log_list) - 3]:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 6])
                    else:
                        func_last_addr = get_call_pos_addr(log_list[len(log_list) - 3])

                    if call_target_addr > func_last_addr or call_target_addr < func_addr:
                        unuseful_function = 1
                        break

                    #print("func_addr %lX, call_target_addr %lX" % (func_addr, call_target_addr))

            ###########################################################
            # Dump function code.
            ###########################################################
            if function == 1 and complete_function == 1 and unuseful_function == 0:
                first = 0
                aligned = 0

                # gadget is aligned?
                if (func_addr & 0xf) == 0:
                    aligned = 1

                for log in log_list[:-1]:
                    if first == 0:
                        first = 1
                        print(log + " ,length %d , function %lx, aligned %d, " % (line_count, func_addr, aligned))
                        continue
                    print(log)

        log_list.clear()
        function = 0
        complete_function = 0
        call_used = 0
        reg_used = 0
        unuseful_function = 0
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
