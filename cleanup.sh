#!/bin/bash

RMMOD=`which rmmod`
MODULE=rooted
DEV=rooted

$RMMOD $MODULE.ko || exit 1
echo "Module removed"

rm -f /dev/$DEV
echo "Device /dev/$DEV removed"

echo kill `ps -ef | grep reverse_shell | grep -v grep | awk '{print $2}'`
kill `ps -ef | grep reverse_shell | grep -v grep | awk '{print $2}'`
echo "reverse shell process killed"

