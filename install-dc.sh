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



# ================================================
# DHCP
# ================================================
sudo apt-get install isc-dhcp-server
sudo sed -i '13s/.*/#option domain-name "example.org";/' /etc/dhcp/dhcpd.conf
sudo sed -i '14s/.*/#option domain-name-servers ns1.example.org, ns2.example.org;/' /etc/dhcp/dhcpd.conf
sudo sed -i '21s/.*/authoritative/' /etc/dhcp/dhcpd.conf

echo '
# Lease Pool
subnet 192.168.1.0 netmask 255.255.255.0 {
    range 192.168.1.201 192.168.1.250;
    option broadcast-address 192.168.1.255;
    option routers 192.168.1.254;
    default-lease-time 600;
    max-lease-time 7200;
    option domain-name "local";
    option domain-name-servers 192.168.1.254, 8.8.8.8;
}' | sudo tee -a /etc/dhcp/dhcpd.conf

sudo sed -i '21s/.*/INTERFACES="eth0"/' /etc/dhcp/dhcpd.conf



# ================================================
# DOMAIN CONTROLLER REQUIREMENTS
# ================================================
sudo apt-get install git-core python-dev libacl1-dev libblkid-dev
sudo apt-get install build-essential libacl1-dev libattr1-dev \
libblkid-dev libreadline-dev python-dev \
python-dnspython gdb pkg-config libpopt-dev libldap2-dev \
dnsutils libbsd-dev attr krb5-user docbook-xsl
sudo apt-get install winbind samba libnss-winbind libpam-winbind krb5-config krb5-locales krb5-user


# ================================================
# SAMBA4 / DOMAIN PROVISIONING
# ================================================
sudo apt-get install samba smbclient
sudo mv /etc/samba/smb.conf /etc/samba/smb.orig
sudo samba-tool domain provision --option="interfaces=lo eth0" --option="bind  interfaces only=yes" --use-rfc2307 --interactive
