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

#range_value = 0x1000
range_value = 0x10

# Check if address is 16 byte-aligned and print function address and call target.
def check_and_print(file_name):
    # Make array and initialization
    matrix = [[0 for x in range(range_value)] for y in range(range_value)]
    function_count = [0, 0]
    call_target_count = [0, 0]
    ALIGNED = 0
    UNALIGNED = 1

    for y in range(range_value):
        for x in range(range_value):
            matrix[y][x] = 0

    file = open(file_name, "r")
    while True:
        log = file.readline()
        if not log:
            break

        result = log.replace(",", "")
        result = ' '.join(result.split())
        data_array = result.split(" ")

        # Check the function address.
        if int(data_array[1], 16) != int(data_array[6], 16):
            print("check function error" + log)
            sys.exit(-1)

        func_addr = int(data_array[6], 16)
        call_target_addr = int(data_array[10], 16)

        if (func_addr & 0xf) != 0:
            function_count[UNALIGNED] = function_count[UNALIGNED] + 1
        else:
            function_count[ALIGNED] = function_count[ALIGNED] + 1

        if (call_target_addr & 0xf) != 0:
            call_target_count[UNALIGNED] = call_target_count[UNALIGNED] + 1
        else:
            call_target_count[ALIGNED] = call_target_count[ALIGNED] + 1

        """
        # for test
        #if (func_addr & 0xf) != 0 or (call_target_addr & 0xf) != 0:
        #    print(("align error %x %x" % (func_addr & 0xf, call_target_addr & 0xf)) + log)
        #    sys.exit(-1)

        #print("%d, %d, %x, %x" % (func_addr & 0xfff, call_target_addr & 0xfff, func_addr & 0xfff, call_target_addr & 0xfff))
        #matrix[call_target_addr & 0xfff][func_addr & 0xfff] = matrix[call_target_addr & 0xfff][func_addr & 0xfff] + 1
        #matrix[call_target_addr & (range_value - 1)][func_addr & (range_value - 1)] = matrix[call_target_addr & (range_value - 1)][func_addr & (range_value - 1)] + 1
        """

    """
    # print for heatmap style
    for y in range(range_value):
        #sys.stdout.write("%d, %d, " % (y, y))
        for x in range(range_value):
            sys.stdout.write("%d, " % matrix[y][x])
        sys.stdout.write("\n")
    """
    print("Function address: total %d, 16 byte-aligned %d, unaligned %d" % (function_count[ALIGNED] + function_count[UNALIGNED], function_count[ALIGNED], function_count[UNALIGNED]));
    print("Call target address: total %d, 16 byte-aligned %d, unaligned %d" % (call_target_count[ALIGNED] + call_target_count[UNALIGNED], call_target_count[ALIGNED], call_target_count[UNALIGNED]));

def main():
    #syscall_name = "00.results/02.syscall_position.txt"
    #function_name = "00.results/00.function_call_gadget_position.txt"
   
    #check_and_print(syscall_name)
    #check_and_print(function_name)
    if len(sys.argv) < 2:
        print("script <file_name>")
        sys.exit(-1)

    check_and_print(sys.argv[1])

if __name__ == "__main__":
    main()
