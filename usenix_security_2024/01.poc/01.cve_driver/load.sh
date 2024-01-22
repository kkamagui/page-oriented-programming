#!/bin/bash
sync

sudo rmmod cve_driver
sudo insmod cve_driver.ko

sudo chmod 777 /dev/cve_config0
sudo dmesg -w
