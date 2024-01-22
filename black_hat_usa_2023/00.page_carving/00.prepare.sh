#!/bin/bash

echo "Preparing the vmlinux file..."

xz -dk vmlinux.xz
mkdir -p 00.results

echo "   [*] Complete"
