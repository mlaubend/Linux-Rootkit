#!/bin/bash

INSMOD=`which insmod`
MODULE=rooted
MAJOR=60
DEV=rooted
MODE=700

echo "Loading module .."
$INSMOD "$MODULE".ko || exit 1

rm -f /dev/$DEV

echo "Creating virtual device /dev/$DEV"
mknod /dev/$DEV c $MAJOR 0

echo "Read /dev/$DEV to see the key logs"
