#!/bin/sh

# primitive script to extract mapping from syscall number to name from Linux headers

echo "#
# Linux syscall numbers
#

SYSCALL_TABLE = {"


cat /usr/include/asm/unistd_32.h \
  | awk '/^#define __NR_.+[[:space:]]+[[:digit:]]+/ { print "  "$3" : \""$2"\"," }' \
  | sed 's/__NR_//'

echo "}"
