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

range_value = 0x1000
# 16 step (16 byte-alined, four points are merged in one)
range_x_div = 4
# 16 step (No merge)
range_y_div = 4

# mode
statistics = 0

# Check if an address is 16 byte-aligned and print the function address and call target.
def check_and_print(file_name):
    # Initialize.
    matrix = [[0 for x in range(range_value)] for y in range(range_value)]
    call_target_count = [0, 0]
    global statistics

    for y in range(range_value):
        for x in range(range_value):
            matrix[y][x] = 0

    call_position = [0 for x in range(range_value)]
    call_target = [0 for x in range(range_value)]

    file = open(file_name, "r")
    while True:
        log = file.readline()
        if not log:
            break

        result = log.replace(",", "")
        result = ' '.join(result.split())
        data_array = result.split(" ")

        # Check function address
        if int(data_array[1], 16) != int(data_array[6], 16):
            print("check function error" + log)
            sys.exit(-1)

        func_addr = int(data_array[6], 16)
        call_target_addr = int(data_array[10], 16)
        call_pos = int(data_array[8], 16)

        #print("%s, %x, %x" % (log, func_addr, call_target_addr))

        # for test
        #if (func_addr & 0xf) != 0 or (call_target_addr & 0xf) != 0:
        #    print(("align error %x %x" % (func_addr & 0xf, call_target_addr & 0xf)) + log)
        #    sys.exit(-1)

        # Check if call target is not 16-byte aligned
        if (call_target_addr & 0xf) != 0:
            call_target_count[1] = call_target_count[1] + 1
        
        call_target_count[0] = call_target_count[0] + 1

        #print("%d, %d, %x, %x" % (func_addr & 0xfff, call_target_addr & 0xfff, func_addr & 0xfff, call_target_addr & 0xfff))
        #matrix[(call_target_addr & 0xfff) >> range_y_div][(func_addr & 0xfff) >> range_x_div] = matrix[(call_target_addr & 0xfff) >> range_y_div][(func_addr & 0xfff) >> range_x_div] + 1
        # collect unaligned branch target
        if (call_target_addr & 0xf) != 0:
            matrix[(call_target_addr & 0xfff) >> range_y_div][(func_addr & 0xfff) >> range_x_div] = matrix[(call_target_addr & 0xfff) >> range_y_div][(func_addr & 0xfff) >> range_x_div] + 1

            # Data for call pos raw
            call_position[(call_pos & 0xfff)>>range_x_div] = call_position[(call_pos & 0xfff)>>range_x_div] + 1
            # Data for call target raw
            call_target[(call_target_addr & 0xfff)>>range_x_div] = call_target[(call_target_addr & 0xfff)>>range_x_div] + 1

    # Print the position data
    os.system("rm -f 00.results/aligned_call_pos_raw.txt")
    for i in range(range_value >> range_x_div):
        os.system('echo "%d %d" >> 00.results/aligned_call_pos_raw.txt' % (i, call_position[i]))

    # Print the call target data
    os.system("rm -f 00.results/aligned_call_target_raw.txt")
    for i in range(range_value >> range_x_div):
        os.system('echo "%d %d" >> 00.results/aligned_call_target_raw.txt' % (i, call_target[i]))

    if statistics == 0:
        # print for heatmap style
        for y in range(range_value >> range_y_div):
            #sys.stdout.write("%d, %d, " % (y, y))
            for x in range(range_value >> range_x_div):
                sys.stdout.write("%d " % matrix[y][x])
            sys.stdout.write("\n")
    else:
        sum_y = [0 for y in range(range_value)]
        for y in range(range_value >> range_y_div):
            for x in range(range_value >> range_x_div):
                sum_y[y] = sum_y[y] + matrix[y][x]
        max_offset_y = 0
        max_y_value = 0
        prev_max_offset_y = 0
        prev_max_y_value = 0
        total_sum = 0
        for y in range(range_value >> range_y_div):
            print("%x, sum %d" % (y, sum_y[y]))
            if max_y_value <= sum_y[y]:
                prev_max_y_value = max_y_value
                prev_max_offset_y = max_offset_y
                max_y_value = sum_y[y]
                max_offset_y = y
            total_sum += sum_y[y]

        print("Total aligned direct call %d, unaligned branch target %d" %(call_target_count[0], call_target_count[1]))
        print("Max y offset %x, max value %d, prev %x, %d, Total sum %d" %(max_offset_y, max_y_value, prev_max_offset_y, prev_max_y_value, total_sum))

def main():
    global statistics
    #syscall_name = "00.results/06.aligned_branch_position_raw.txt"
   
    #check_and_print(syscall_name)
    if len(sys.argv) < 2:
        print("script <file_name> <statistics: 1>")
        sys.exit(-1)

    if len(sys.argv) > 2:
        statistics = int(sys.argv[2])

    check_and_print(sys.argv[1])

if __name__ == "__main__":
    main()
