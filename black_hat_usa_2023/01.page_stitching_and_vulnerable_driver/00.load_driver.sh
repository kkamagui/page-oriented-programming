#!/bin/bash
sync
sudo rmmod lc_driver

echo "PoC driver starts on the CPU 0 ..."
sudo taskset -c 0 insmod lc_driver.ko
echo "   [*] Complete"

sudo chmod 777 /dev/lostctrl
sudo dmesg
#sudo dmesg -w
