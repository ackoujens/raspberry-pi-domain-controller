#!/bin/bash

# Raspberry Pi Raspbian Domain Controller
# Author: Jens Ackou



# ================================================
# SCRIPT SETUP
# ================================================

# Quit on error
set -e

# Horizontal line
_hLine="------------------------------------------------------------------------------------"

# Colorized INFO output
function _info() {
  COLOR='\033[00;32m' # green
  RESET='\033[00;00m' # white
  echo "${COLOR}${@}${RESET}"
}

# Colorized WARNING output
function _warn() {
  COLOR='\033[00;31m' # red
  RESET='\033[00;00m' # white
  echo "${COLOR}${@}${RESET}"
}

# Introduction (Font: Doom)
_info '
____________ _
| ___ \ ___ (_)
| |_/ / |_/ /_
|    /|  __/| |
| |\ \| |   | |
\_| \_\_|   |_|
______                _     _
| ___ \              | |   (_)
| |_/ /__ _ ___ _ __ | |__  _  __ _ _ __
|    // _` / __|  _ \|  _ \| |/ _` |  _ \
| |\ \ (_| \__ \ |_) | |_) | | (_| | | | |
\_| \_\__,_|___/ .__/|_.__/|_|\__,_|_| |_|
               | |
               |_|
______                      _         _____             _             _ _
|  _  \                    (_)       /  __ \           | |           | | |
| | | |___  _ __ ___   __ _ _ _ __   | /  \/ ___  _ __ | |_ _ __ ___ | | | ___ _ __
| | | / _ \|  _ ` _ \ / _` | |  _ \  | |    / _ \|  _ \| __|  __/ _ \| | |/ _ \  __|
| |/ / (_) | | | | | | (_| | | | | | | \__/\ (_) | | | | |_| | | (_) | | |  __/ |
|___/ \___/|_| |_| |_|\__,_|_|_| |_|  \____/\___/|_| |_|\__|_|  \___/|_|_|\___|_|

'



# ================================================
# UPDATE/UPGRADE
# ================================================
sudo apt-get update
sudo apt-get upgrade



# ================================================
# STATIC IP ADDRESS
# ================================================
echo '
# Static IP
interface eth0
static routers=192.168.1.1
static domain_name_servers=192.168.1.200 192.168.1.1
static ip_address=192.168.1.200
static domain_search=volvovalorvlogs.com' >> /etc/dhcpcd.conf



# ================================================
# HOSTNAME
# ================================================
sudo rm /etc/hostname
sudo touch /etc/hostname
echo "dc1" | sudo tee /etc/hostname

sudo rm /etc/hosts
echo '127.0.0.1       localhost.localdomain localhost
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

127.0.1.1       dc1.volvovalorvlogs.com dc1
' | sudo tee /etc/hosts



# ================================================
# DNS
# ================================================
sudo rm /etc/resolv.conf
sudo touch /etc/resolv.conf
echo 'domain volvovalorvlogs.com
search volvovalorvlogs.com
nameserver 192.168.1.200
nameserver 192.168.1.1' | sudo tee /etc/resolv.conf
sudo chattr +i /etc/resolv.conf
