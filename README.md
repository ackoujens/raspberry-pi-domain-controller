# Raspberry Pi Raspbian Domain Controller
Convert your Raspberry Pi into a legit DC.
Ideal for hobby purposes considering the low power consumption of the Pi!

## How to use
Run the command below to run the script on your Raspbian install over ssh
`bash <(curl -s https://raw.githubusercontent.com/ackoujens/raspberry-pi-raspbian-domain-controller/master/install-dc.sh)`

## Features
- Runs remotely from GitHub raw
- DNS server
- DHCP server
- Samba4 domain provisioning
- Kerberos authentication

## Todo
- Domain controller functionality
- Domain needs to be enforced in capital letters where needed
- Change enxb827eb3306a3 replacement to detecting of the interface name through ipconfig
- Menu system
