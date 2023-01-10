#!/bin/bash

# REFE: http://c.biancheng.net/linux/echo.html
BLUE=$(tput setaf 6)
RESET=$(tput sgr0)

echo -e "${BLUE}NOTE: This script only applies to my network adapter and IP configuration,"
echo -e "      please refer to the report to modify the command in this script.${RESET}"

echo -e "${BLUE}[1/5] Enabling IP forward...${RESET}"
sudo sysctl net.ipv4.ip_forward=1

echo -e "${BLUE}[2/5] Deleting all rules in iptables...${RESET}"
sudo iptables -F

echo -e "${BLUE}[3/5] Changing policy on forward to accept...${RESET}"
sudo iptables -P FORWARD ACCEPT

echo -e "${BLUE}[4/5] Listing the rules in iptables on forward..."
echo -e "      Please check the rule set is empty and the policy on forward is accept.${RESET}"
sudo iptables -nL FORWARD

echo -e "${BLUE}[5/5] Adding required routes..."
echo -e "      The IP address and network adapter should be modified by your configuration.${RESET}"
sudo route add -net 10.0.12.0/24 ens37
sudo route add -net 192.168.44.0/24 ens38

echo -e "${BLUE}INFO: Forward Settings done, please check by ping between machines.${RESET}"
