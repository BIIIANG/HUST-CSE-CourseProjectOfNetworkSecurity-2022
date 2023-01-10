#!/bin/bash

# REFE: http://c.biancheng.net/linux/echo.html
BLUE=$(tput setaf 6)
RESET=$(tput sgr0)

curr_path=$(pwd)
xwall_path=$(echo $XWALL_PATH)

echo -e "${BLUE}- Checking xwall path...${RESET}"
if [ -z "$xwall_path" ]; then
    echo -e "The xwall path is null, please set it by 'export XWALL_PATH=xxx'."
    exit
else 
    echo -e "The xwall path is ${xwall_path}."
fi

echo -e "${BLUE}- Cleaning xwall module...${RESET}"
cd $xwall_path/module
make clean
cd $curr_path

echo -e "${BLUE}- Cleaning CLI program...${RESET}"
cd $xwall_path/cli
make clean
cd $curr_path

echo -e "${BLUE}- Removing xwall module...${RESET}"
ps -aux | grep xwall_app.py | grep -v grep | awk '{print $2}' | xargs kill >/dev/null 2>&1
sudo rmmod xwall.ko

echo -e "${BLUE}- Clean done.${RESET}"

