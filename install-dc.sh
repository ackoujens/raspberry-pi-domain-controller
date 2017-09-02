#!/bin/bash

# Raspberry Pi Raspbian Domain Controller
# Author: Jens Ackou



# ================================================
# SCRIPT SETUP
# ================================================

# Quit on error
set -e

# Introduction (Font: Doom)
echo '
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

' > whiptail_intro
whiptail --textbox whiptail_intro 20 84




# ================================================
# SECURITY
# ================================================
set_password_pi() {
  while [[ -z $password_result ]] || [[ $password_result == "1" ]] ; do
      pipasswd1=$(whiptail --passwordbox "Enter new password for pi:" 10 60 3>&1 1>&2 2>&3)
      pipasswd2=$(whiptail --passwordbox "Repeat new password for pi:" 10 60 3>&1 1>&2 2>&3)
      if [ $pipasswd1 != $pipasswd2 ]; then
          whiptail --msgbox "Passwords do not match" 10 60
          ! true
      fi
      password_result=$?
  done
  echo -e "$pipasswd1\n$pipasswd2" | passwd pi
}
# set_password_pi

set_password_root(){
    while [[ -z $password_result ]] || [[ $password_result == "1" ]] ; do
        rootpasswd1=$(whiptail --passwordbox "Enter new password for root:" 10 60 3>&1 1>&2 2>&3)
        rootpasswd2=$(whiptail --passwordbox "Repeat new password for root:" 10 60 3>&1 1>&2 2>&3)
        if [ $rootpasswd1 != $rootpasswd2 ]; then
            whiptail --msgbox "Passwords do not match" 10 60
            ! true
        fi
        password_result=$?
    done
    echo -e "$rootpasswd1\n$rootpasswd2" | passwd root
}
# set_password_root



# ================================================
# UPDATE
# ================================================
do_update() {
  apt-get -y update &&
  apt-get -y upgrade
}
# do_update



# ================================================
# NETWORK SETUP
# ================================================
HWADDR=`ifconfig enxb827eb3306a3 | grep HW | awk ' BEGIN { FS = " " } ; { print $5 } ; '`
IPADDR=`ifconfig enxb827eb3306a3 | grep "inet addr:" | awk $'{print $2}' | cut -d ":" -f 2`
ISDHCP=`grep dhcp /etc/network/interfaces | awk $'{print $4}'`
GW=`ip route list | grep default | awk $'{print $3}'`

octet="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
ip4="^$octet\\.$octet\\.$octet\\.$octet$"

hostn=""
hostname_result=""
mode=""

hostname_file="/etc/hostname"
hosts_file="/etc/hosts"
dns_file="/etc/resolv.conf"
interfaces_file="/etc/network/interfaces"

set_hostname(){
    # set_hostname HOSTNAME DOMAINNAME
    sudo bash -c "echo '$1' > $hostname_file"

    sudo bash -c "echo '127.0.0.1       localhost' > $hosts_file"
    sudo bash -c "echo '127.0.1.1       $1.$2     $1' >> $hosts_file"
    sudo bash -c "echo '::1             localhost ip6-localhost ip6-loopback' >> $hosts_file"
    sudo bash -c "echo 'ff02::1         ip6-allnodes' >> $hosts_file"
    sudo bash -c "echo 'ff02::2         ip6-allrouters' >> $hosts_file"
}

set_static_net(){
    # set_static_net IP SUBNET GATEWAY
    sudo bash -c "echo 'auto lo' > $interfaces_file"
    sudo bash -c "echo 'iface lo inet loopback' >> $interfaces_file"
    sudo bash -c "echo ''  >> $interfaces_file"
    sudo bash -c "echo 'auto enxb827eb3306a3' >> $interfaces_file"
    sudo bash -c "echo 'iface enxb827eb3306a3 inet static' >> $interfaces_file"
    sudo bash -c "echo '  address $1' >> $interfaces_file"
    sudo bash -c "echo '  netmask $2' >> $interfaces_file"
    sudo bash -c "echo '  gateway $3' >> $interfaces_file"
}

set_dns_domain(){
    # set_dns_domain DNSSERVER DOMAINNAME
    if [ -z "$2" ] || [ "$2" = "adv.ru" ]; then
        sudo bash -c "echo 'domain adv.ru'  > $dns_file"
        sudo bash -c "echo 'search adv.ru adv.local.' >> $dns_file"
    else
        sudo bash -c "echo 'domain $2'  > $dns_file"
        sudo bash -c "echo 'search $2' >> $dns_file"
    fi
    sudo bash -c "echo 'nameserver $1' >> $dns_file"
}

setup_network() {
  while [ -z $result ] || [ $result == "1" ] ; do

      while [[ -z $ip_result ]] || [[ $ip_result == "1" ]] ; do
          ipaddr=$(whiptail --backtitle "Network Setup" --inputbox "IP Address" 10 60 "192.168.1.200" 3>&1 1>&2 2>&3)
          if ! [[ $ipaddr =~ $ip4 ]]; then
              whiptail --msgbox "Invalid IP!" 10 60
              ! true
          fi
          ip_result=$?
      done

      netmask=$(whiptail --backtitle "Network Setup" --backtitle "Domain Controller Setup" --inputbox "Network Mask" 10 60 "255.255.255.0" 3>&1 1>&2 2>&3)
      gateway=$(whiptail --backtitle "Network Setup" --inputbox "Gateway" 10 60 "192.168.1.1" 3>&1 1>&2 2>&3)
      dns1=$(whiptail --backtitle "Network Setup" --inputbox "DNS" 10 60 "192.168.1.1" 3>&1 1>&2 2>&3)
      domain=$(whiptail --backtitle "Network Setup" --inputbox "Domain Name" 10 60 "mydomain.ext" 3>&1 1>&2 2>&3)
      whiptail --backtitle "Network Setup" --title "Are the settings correct?" --yesno "\n IP Adress: $ipaddr \n Netmask: $netmask \n Gateway: $gateway \n DNS: $dns1 \n Domain: $domain \n" 18 78 3>&1 1>&2 2>&3
      result=$?
  done
}
#setup_network
#set_hostname $hostn $domain
#set_static_net $ipaddr $netmask $gateway
#set_dns_domain $dns1 $domain



# ================================================
# DHCP SERVER (TODO)
# ================================================
install_dhcp_server() {
  sudo apt-get install isc-dhcp-server
}

setup_dhcp_server() {
  #sudo sed -i '13s/.*/#option domain-name "example.org";/' /etc/dhcp/dhcpd.conf
  #sudo sed -i '14s/.*/#option domain-name-servers ns1.example.org, ns2.example.org;/' /etc/dhcp/dhcpd.conf
  #sudo sed -i '21s/.*/authoritative/' /etc/dhcp/dhcpd.conf

  subnet=$(whiptail --backtitle "DHCP Server" --backtitle "Domain Controller Setup" --inputbox "Lease pool start" 10 60 "192.168.1.201" 3>&1 1>&2 2>&3)
  netmask=$(whiptail --backtitle "DHCP Server" --backtitle "Domain Controller Setup" --inputbox "Lease pool start" 10 60 "192.168.1.201" 3>&1 1>&2 2>&3)
  poolstart=$(whiptail --backtitle "DHCP Server" --backtitle "Domain Controller Setup" --inputbox "Lease pool start" 10 60 "192.168.1.201" 3>&1 1>&2 2>&3)
  poolend=$(whiptail --backtitle "DHCP Server" --backtitle "Domain Controller Setup" --inputbox "Lease pool start" 10 60 "192.168.1.201" 3>&1 1>&2 2>&3)

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

  #sudo sed -i '21s/.*/INTERFACES="enxb827eb3306a3"/' /etc/dhcp/dhcpd.conf
}
setup_dhcp_server


# ================================================
# DOMAIN CONTROLLER REQUIREMENTS
# ================================================
install_dc_req() {
  sudo apt-get install git-core python-dev libacl1-dev libblkid-dev
  sudo apt-get install build-essential libacl1-dev libattr1-dev \
  libblkid-dev libreadline-dev python-dev \
  python-dnspython gdb pkg-config libpopt-dev libldap2-dev \
  dnsutils libbsd-dev attr krb5-user docbook-xsl
  sudo apt-get install winbind samba libnss-winbind libpam-winbind krb5-config krb5-locales krb5-user
}



# ================================================
# SAMBA4 / DOMAIN PROVISIONING (TODO)
# ================================================
setup_samba() {
  sudo apt-get install samba smbclient
  sudo mv /etc/samba/smb.conf /etc/samba/smb.orig
  #sudo samba-tool domain provision --option="interfaces=lo enxb827eb3306a3" --option="bind  interfaces only=yes" --use-rfc2307 --interactive
}



# ================================================
# KERBEROS
# ================================================
setup_kerberos() {
  cd /etc
  sudo cp /var/lib/samba/private/krb5.conf ./
}



# ================================================
# TESTING
# ================================================

test() {
  echo "PASSWORD TEST"
  echo "Old pi password: " + $pipasswd1
  echo "New pi password: " + $pipasswd2
  echo $domain
}
echo $domain
test
