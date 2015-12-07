##########################
## DEBIAN FIRST INSTALL ##
##########################

#### DESCRIPTION ####
This script is designed to install various softwares on Debian. 
Some such as vim, most, or pigz are installed and configured for an easier use of Debian. A customization of the .bashrc is also performed. 
In a second part, the script installs security softwares such as an anti-rootkit (rkhunter) and a port scanner blocker (portsentry).
Finally, it setups a firewall with iptables.

#### HOW TO ####
apt-get update;
apt-get install -y git-core;
git clone https://github.com/h3rX9m/debian-first-install.git;
cd debian-first-install;
chmod +x install.sh && ./install.sh;
or chmod +x install_VM_debian.sh && ./install_VM_debian.sh;

#### LICENSE ####
MIT. See 'LICENSE' for more details
