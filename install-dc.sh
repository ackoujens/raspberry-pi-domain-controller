#!/bin/bash

# Raspberry Pi Raspbian Domain Controller
# Author: Jens Ackou

#https://raw.githubusercontent.com/asb/raspi-config/master/raspi-config
#https://en.wikibooks.org/wiki/Bash_Shell_Scripting/Whiptail
#https://www.madirish.net/566
#https://help.dreamhost.com/hc/en-us/articles/216499537-How-to-configure-passwordless-login-in-Mac-OS-X-and-Linux

# ================================================
# SCRIPT SETUP
# ================================================
# Quit on error
set -e

# Global variables
TITLE="RPi Raspbian Domain Controller"

# Use menu interface or run entire config in 1 go
# deploy
# config
MODE=$1

# Display message
function displayMessage() {
    whiptail --title "$1" --msgbox "$2" 8 78
}

# Replace text in a specific file
function replaceText() {
  sudo sed -i '/'"$2"'/c\'"$3"'' $1
}

function appendText() {
  sudo bash -c "echo '$2' >> $1"
}

function findFile() {
  if [ -f $1 ]; then
    return 1
  fi
  return 0
}

function backupFile() {
  findFile "$1.BAK"
  if [[ ! ${?} ]]; then
    sudo \cp $1 $1.BAK
  fi
}

function restoreFile() {
  findFile "$1.BAK"
  if [[ ${?} ]]; then
    sudo \cp $1.BAK $1
  fi
}

# Print script title (Font: Doom)
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
  backupFile /etc/ssh/sshd_config
  displayMessage "Enable root" "You need to enable root to secure it's password afterwards."
  if whiptail --yesno "Are you sure you want to enable the root user account?" 0 0; then
    replaceText /etc/ssh/sshd_config "PermitRootLogin without-password" "PermitRootLogin yes"
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
  locked_status=$(passwd -S pi | awk '{print $2;}')
  locked=$?
  if [ ${locked_status} = "L" ]; then
    locked=1
  else
    locked=0
  fi

  if [ ${locked} = 1 ]; then
    if whiptail --yesno "Are you sure you want to unlock the pi user account?" 0 0; then
      sudo passwd --unlock pi
    fi
  fi

  if [ ${locked} = 0 ]; then
    if whiptail --yesno "Are you sure you want to lock the pi user account?" 0 0; then
      sudo passwd --lock pi
    fi
  fi
}



# ================================================
# SECURITY - SSH
# ================================================
disable_ssh_root() {
  backupFile /etc/ssh/sshd_config
  if whiptail --yesno "Are you sure you want to lock ssh for root?" 0 0; then
    replaceText "/etc/ssh/sshd_config" "#LoginGraceTime 2m"                 "LoginGraceTime 120"
    replaceText "/etc/ssh/sshd_config" "#PermitRootLogin prohibit-password" "PermitRootLogin no"
    replaceText "/etc/ssh/sshd_config" "#StrictModes yes"                   "StrictModes yes"
    replaceText "/etc/ssh/sshd_config" "#PubkeyAuthentication yes" "PubkeyAuthentication yes"
    replaceText "/etc/ssh/sshd_config" "#AuthorizedKeysFile      .ssh/authorized_keys .ssh/authorized_keys2" "AuthorizedKeysFile      %h/.ssh/authorized_keys"
    replaceText "/etc/ssh/sshd_config" "#PermitEmptyPasswords no" "PermitEmptyPasswords no"
    replaceText "/etc/ssh/sshd_config" "#PasswordAuthentication yes" "PasswordAuthentication no"
    grep -q -F 'RSAAuthentication yes' /etc/ssh/sshd_config || sudo bash -c "echo 'RSAAuthentication yes' >> /etc/ssh/sshd_config"
  fi
}

disable_pam() {
  backupFile /etc/ssh/sshd_config
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
# SECURITY - FIREWALL
# ================================================
# iptables is a firewall package
#sudo apt-get install iptables iptables-persistent

# Check current iptables rules
#sudo /sbin/iptables -L

# Save in text file and edit them
#sudo /sbin/iptables-save > /etc/iptables/rules.v4

#sudo cat /etc/iptables/rules.v4
#:INPUT ACCEPT [0:0]
#:FORWARD ACCEPT [0:0]
#:OUTPUT ACCEPT [0:0]

# Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
#-A INPUT -i lo -j ACCEPT
#-A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

# Accepts all established inbound connections
#-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allows all outbound traffic
# You could modify this to only allow certain traffic
#-A OUTPUT -j ACCEPT

# Allows SSH connections
# The --dport number is the same as in /etc/ssh/sshd_config
#-A INPUT -p tcp -m state --state NEW --dport 22 -j ACCEPT

# log iptables denied calls (access via 'dmesg' command)
#-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Reject all other inbound - default deny unless explicitly allowed policy:
#-A INPUT -j REJECT
#-A FORWARD -j REJECT

#COMMIT

# Apply changes
#sudo /usr/sbin/iptables-apply /etc/iptables/rules.v4

# Check new rules
#sudo /sbin/iptables -L



# ================================================
# SECURITY - AUTOMATED UPDATES
# ================================================
#https://wiki.debian.org/UnattendedUpgrades
#sudo apt-get -y install unattended-upgrades apt-listchanges



# ================================================
# SECURITY - LOGWATCH
# ================================================
#sudo apt-get install logwatch

# Adjust config to needs
#/usr/share/logwatch/default.conf/logwatch.conf

# By def logwatch will mail root account, alter this by editing /etc/aliases
# Point to your e-mail address
#/etc/aliases

#sudo /usr/bin/newaliases



# ================================================
# NETWORK SETUP - NETWORK CONFIGURATION
# ================================================
INTERFACE='ifconfig | head -n1 | awk $"{print $1}" | cut -d ":" -f 1'
HWADDR=`ifconfig $INTERFACE | grep HW | awk ' BEGIN { FS = " " } ; { print $5 } ; '`
IPADDR=`ifconfig $INTERFACE | grep "inet addr:" | awk $'{print $2}' | cut -d ":" -f 2`
ISDHCP=`grep dhcp /etc/network/interfaces | awk $'{print $4}'`
GW=`ip route list | grep default | awk $'{print $3}'`

octet="(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
ip4="^$octet\\.$octet\\.$octet\\.$octet$"

hostn="DCPI"

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
  sudo bash -c "echo 'auto $INTERFACE' >> $interfaces_file"
  sudo bash -c "echo 'iface $INTERFACE inet static' >> $interfaces_file"
  sudo bash -c "echo '  address $1' >> $interfaces_file"
  sudo bash -c "echo '  netmask $2' >> $interfaces_file"
  sudo bash -c "echo '  gateway $3' >> $interfaces_file"
}

set_dns_domain(){
  sudo bash -c "echo 'domain $2'  > $dns_file"
  sudo bash -c "echo 'search $2' >> $dns_file"
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
      set_hostname $hostn $domain
      set_static_net $ipaddr $netmask $gateway
      set_dns_domain $dns1 $domain
  done
}




# ================================================
# DHCP SERVER (TODO)
# ================================================
install_dhcp_server() {
  sudo apt-get -y install isc-dhcp-server
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

  sudo sed -i '21s/.*/INTERFACES="enxb827eb3306a3"/' /etc/dhcp/dhcpd.conf
}


# ================================================
# DOMAIN CONTROLLER REQUIREMENTS
# ================================================
install_dc_req() {
  sudo apt-get -y install git-core python-dev libacl1-dev libblkid-dev
  sudo apt-get -y install build-essential libacl1-dev libattr1-dev \
  libblkid-dev libreadline-dev python-dev \
  python-dnspython gdb pkg-config libpopt-dev libldap2-dev \
  dnsutils libbsd-dev attr krb5-user docbook-xsl
  sudo apt-get -y install winbind samba libnss-winbind libpam-winbind krb5-config krb5-locales krb5-user
}



# ================================================
# SAMBA4 / DOMAIN PROVISIONING (TODO)
# ================================================
setup_samba() {
  sudo apt-get -y install samba smbclient
  sudo mv /etc/samba/smb.conf /etc/samba/smb.orig
  sudo samba-tool domain provision --option="interfaces=lo enxb827eb3306a3" --option="bind  interfaces only=yes" --use-rfc2307 --interactive
}



# ================================================
# KERBEROS
# ================================================
setup_kerberos() {
  cd /etc
  sudo cp /var/lib/samba/private/krb5.conf ./
}



# ================================================
# MENU - Security
# ================================================
do_security_menu() {
  menu=$(whiptail --title "$TITLE" --menu "Security" --ok-button Select --cancel-button Back 20 78 10 \
      "1" "User Accounts" \
      "2" "Securing SSH" \
      "3" "Firewall" \
      "4" "Automated Updates" \
      "5" "Logwatch" \
      3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ ${exitstatus} = 1 ]; then
      return 0
    elif [ ${exitstatus} = 0 ]; then
      case ${menu} in
        1) do_user_accounts_menu ;;
        2) do_securing_ssh_menu ;;
        3) do_firewall_menu ;;
        4) do_automated_updates_menu ;;
        5) do_logwatch_menu ;;
      esac || whiptail --msgbox "There was an error running option $menu" 20 60 1
      do_security_menu
    fi
}

do_user_accounts_menu() {
  menu=$(whiptail --title "$TITLE" --menu "User Accounts" --ok-button Select --cancel-button Back 20 78 10 \
      "1" "Enable root" \
      "2" "Change root password" \
      "3" "Create new sudo user account" \
      "4" "Lock/Unlock pi user account" \
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
        1) set_hostname ;;
        2) setup_network ;;
        3) clear_authorized_keys ;;
        4) add_authorized_key ;;
      esac || whiptail --msgbox "There was an error running option $menu" 20 60 1
      do_securing_ssh_menu
    fi
}



# ================================================
# MENU - Network
# ================================================
do_network_menu() {
  menu=$(whiptail --title "$TITLE" --menu "Networking" --ok-button Select --cancel-button Back 20 78 10 \
      "1" "Setup network" \
      "2" "DHCP server configuration" \
      3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ ${exitstatus} = 1 ]; then
      return 0
    elif [ ${exitstatus} = 0 ]; then
      case ${menu} in
        1) setup_network ;;
        2) setup_dhcp_server ;;
      esac || whiptail --msgbox "There was an error running option $menu" 20 60 1
      do_network_menu
    fi
}

while true; do
  menu=$(whiptail --title "$TITLE" --menu "Perform these procedures in a chronological order." --ok-button Select --cancel-button Quit 20 78 10 \
    "1" "Update" \
    "2" "Security" \
    "3" "Network" \
    "4" "Install DC Requirements" \
    "5" "Setup Samba" \
    "6" "Setup Kerberos" \
    3>&1 1>&2 2>&3)

  exitstatus=$?
  if [ ${exitstatus} = 1 ]; then
    return 0
  elif [ ${exitstatus} = 0 ]; then
    case ${menu} in
      1) do_update ;;
      2) do_security_menu ;;
      3) do_network_menu ;;
      4) install_dc_req ;;
      5) setup_samba ;;
      6) setup_kerberos ;;
    esac || whiptail --msgbox "There was an error running option $menu" 20 60 1
  else
    exit 1
  fi
done
