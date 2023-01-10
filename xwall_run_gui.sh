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

echo -e "${BLUE}- Killing old process...${RESET}"
ps -aux | grep xwall_app.py | grep -v grep | awk '{print $2}' | xargs kill >/dev/null 2>&1
sudo rmmod xwall >/dev/null  2>&1

echo -e "${BLUE}- Compiling xwall module...${RESET}"
cd $xwall_path/module
make
cd $curr_path

echo -e "${BLUE}- Compiling CLI program...${RESET}"
cd $xwall_path/cli
make
cd $curr_path

echo -e "${BLUE}- Installing xwall module...${RESET}"
sudo insmod $xwall_path/module/xwall.ko

echo -e "${BLUE}- Starting GUI backend server...${RESET}"
python3 $xwall_path/gui/xwall_app.py &

echo -e "${BLUE}- Installing library libfuse2 for GUI...${RESET}"
sudo apt install libfuse2

echo -e "${BLUE}- Starting GUI program...${RESET}"
$xwall_path/gui/xwall-gui-0.1.0.AppImage &

# Wait for last process.
wait $!

ps -aux | grep xwall_app.py | grep -v grep | awk '{print $2}' | xargs kill
sudo rmmod xwall

