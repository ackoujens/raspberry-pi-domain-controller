#!/bin/bash

# Raspberry Pi Raspbian Domain Controller
# Author: Jens Ackou



# ================================================
# SCRIPT SETUP
# ================================================
# Global variables
TITLE="RPi Raspbian Domain Controller"

# Quit on error
set -e

# Display message
function displayMessage() {
    whiptail --title "$1" --msgbox "$2" 8 78
}

# Replace text in a specific file
function replaceText() {
  sudo sed -i '/'"$2"'/c\'"$3"'' $1
}

function appendText() {
  echo $2 >> $1
}

# Introduction (Font: Doom)
echo '                ______                _     _
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
whiptail --textbox whiptail_intro 21 88
rm whiptail_intro



# ================================================
# UPDATE
# ================================================
do_update() {
  if whiptail --yesno "Are you sure you want to update your RPi?" 0 0; then
    sudo apt-get -y update && sudo apt-get -y upgrade
  fi
}



# ================================================
# SECURITY - USER ACCOUNTS
# ================================================
enable_root() {
  displayMessage "Enable root" "You need to enable root to secure it's password afterwards."
  if whiptail --yesno "Are you sure you want to enable the root user account?" 0 0; then
    sudo sed -i '/PermitRootLogin without-password/c\PermitRootLogin yes' /etc/ssh/sshd_config
    displayMessage "Enable root" "Your RPi will now reboot. Ssh back into it after reboot is completed."
    sudo reboot now
  fi
}

set_password() {
  while [[ -z $password_result ]] || [[ $password_result == "1" ]] ; do
      passwd1=$(whiptail --passwordbox "Enter new password for $1:" 10 60 3>&1 1>&2 2>&3)
      passwd2=$(whiptail --passwordbox "Repeat new password for $1:" 10 60 3>&1 1>&2 2>&3)

      exitstatus=$?
      if [ ${exitstatus} = 1 ]; then
        return 0
      elif [ $passwd1 != $passwd2 ]; then
        whiptail --msgbox "Passwords do not match" 10 60
        ! true
      fi
      password_result=$?
  done
  echo -e "$passwd1\n$passwd2" | sudo passwd $1
}

create_sudo_user() {
  displayMessage "Create new sudo user" "Creating a new sudo user prevents predictable attacks using the default pi account."
  user=$(whiptail --backtitle "Create new sudo user" --inputbox "Username" 10 60 "dcpi" 3>&1 1>&2 2>&3)
  if whiptail --yesno "Are you sure you want to create the $user user account?" 0 0; then
    sudo adduser $user
    sudo usermod -aG sudo $user
    displayMessage "Create new sude user" "Your RPi will now reboot. Ssh back into it with $user after reboot is completed."
    sudo reboot now
  fi
}

lock_user() {
  locked_status="$(passwd -S $1 | awk '{print $2;}')"
  locked=$?
  if ${locked_status} = L ; then
    locked=1
  else
    locked=0
  fi

  if ${locked} || whiptail --yesno "Are you sure you want to unlock the pi user account?" 0 0; then
    sudo passwd --unlock $1
  elif whiptail --yesno "Are you sure you want to lock the pi user account?" 0 0; then
    sudo passwd --lock $1
  fi
}



# ================================================
# SECURITY - SSH
# ================================================
disable_ssh_root() {
  if whiptail --yesno "Are you sure you want to lock ssh for root?" 0 0; then
    replaceText "/etc/ssh/sshd_config" "#LoginGraceTime 2m"                 "LoginGraceTime 120"
    replaceText "/etc/ssh/sshd_config" "#PermitRootLogin prohibit-password" "PermitRootLogin no"
    replaceText "/etc/ssh/sshd_config" "#StrictModes yes"                   "StrictModes yes"
    replaceText "/etc/ssh/sshd_config" "#PubkeyAuthentication yes" "PubkeyAuthentication yes"

    # TODO Needs to be tested on new build
    replaceText "/etc/ssh/sshd_config" "AuthorizedKeysFile      %h/.ssh/authorized_keys .ssh/authorized_keys2" "AuthorizedKeysFile      %h/.ssh/authorized_keys"

    replaceText "/etc/ssh/sshd_config" "#PermitEmptyPasswords no" "PermitEmptyPasswords no"
    replaceText "/etc/ssh/sshd_config" "#PasswordAuthentication yes" "PasswordAuthentication no"

    # TODO Append this if not present
    #RSAAuthentication yes
  fi
}

disable_pam() {
  if whiptail --yesno "Are you sure you want to disable PAM?" 0 0; then
    replaceText "/etc/ssh/sshd_config" "UsePAM yes" "UsePAM no"
    mkdir ~/.ssh
    chmod 0700 ~/.ssh
    touch ~/.ssh/authorized_keys
    chmod 0600 ~/.ssh/authorized_keys
  fi
}

clear_authorized_keys() {
  if whiptail --yesno "Are you sure you want to clear all SSH keys from the list?" 0 0; then
    sudo rm ~/.ssh/authorized_keys
    touch ~/.ssh/authorized_keys
    chmod 0600 ~/.ssh/authorized_keys
  fi
}

add_authorized_key() {
  key=$(whiptail --backtitle "SSH" --inputbox "Add SSH key" 10 60 3>&1 1>&2 2>&3)
  if whiptail --yesno "Are you sure you want to add this SSH key?" 0 0; then
    appendText "~/.ssh/authorized_keys" $key
  fi
}



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
#setup_dhcp_server


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
# MENU SELECTION
# ================================================
do_security_menu() {
  menu=$(whiptail --title "$TITLE" --menu "Security" --ok-button Select --cancel-button Back 20 78 10 \
      "1" "Update" \
      "2" "User Accounts" \
      "3" "Securing SSH" \
      "4" "Firewall" \
      "5" "Automated Updates" \
      "6" "Logwatch" \
      3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ ${exitstatus} = 1 ]; then
      return 0
    elif [ ${exitstatus} = 0 ]; then
      case ${menu} in
        1) do_update ;;
        2) do_user_accounts_menu ;;
        3) do_securing_ssh_menu ;;
        4) do_firewall_menu ;;
        5) do_automated_updates_menu ;;
        6) do_logwatch_menu ;;
      esac || whiptail --msgbox "There was an error running option $menu" 20 60 1
      do_security_menu
    fi
}

do_user_accounts_menu() {
  menu=$(whiptail --title "$TITLE" --menu "User Accounts" --ok-button Select --cancel-button Back 20 78 10 \
      "1" "Enable root" \
      "2" "Change root password" \
      "3" "Create new sudo user account" \
      "4" "Lock down pi user account" \
      3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ ${exitstatus} = 1 ]; then
      return 0
    elif [ ${exitstatus} = 0 ]; then
      case ${menu} in
        1) enable_root ;;
        2) set_password root ;;
        3) create_sudo_user ;;
        4) lock_user pi ;;
      esac || whiptail --msgbox "There was an error running option $menu" 20 60 1
      do_user_accounts_menu
    fi
}

do_securing_ssh_menu() {
  menu=$(whiptail --title "$TITLE" --menu "Securing ssh" --ok-button Select --cancel-button Back 20 78 10 \
      "1" "Disable root login" \
      "2" "Disable Pluggable Authentication Modules (PAM)" \
      "3" "Enable/Clear Authorized Keys" \
      "4" "Add Authorized Key" \
      3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ ${exitstatus} = 1 ]; then
      return 0
    elif [ ${exitstatus} = 0 ]; then
      case ${menu} in
        1) disable_ssh_root ;;
        2) disable_pam ;;
        3) clear_authorized_keys ;;
        4) add_authorized_key ;;
      esac || whiptail --msgbox "There was an error running option $menu" 20 60 1
      do_user_accounts_menu
    fi
}

while true; do
  menu=$(whiptail --title "$TITLE" --menu "Perform these procedures in a chronological order." --ok-button Select --cancel-button Quit 20 78 10 \
    "1" "Security" \
    3>&1 1>&2 2>&3)

  exitstatus=$?
  if [ ${exitstatus} = 1 ]; then
    return 0
  elif [ ${exitstatus} = 0 ]; then
    case ${menu} in
      1) do_security_menu ;;
    esac || whiptail --msgbox "There was an error running option $menu" 20 60 1
  else
    exit 1
  fi
done
