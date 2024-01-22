#!/bin/bash

sudo rmmod dump
sudo insmod dump.ko
sudo chmod 777 /dev/dump

sudo journalctl -f -k
