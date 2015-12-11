# !/bin/bash
# Template_scripts.sh
# Aurélien Partonnaud - 2015
# Free to use on a Debian 8
# Tested on a minimal Debian 64bits
clear

#### FORMATTING VARIABLES ####
NORMAL=$(tput sgr0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
WHITE=$(tput setaf 7)
# Mail address to receive the monitorings
MONITORING=""
# Users who can connect with ssh - root is forbidden - e.g. "user1 user2 user3"
SSH_USERS=""
# Users who can use sudo - root is forbidden - e.g. "user1 user2 user3"
SUDO_USERS=""
# Users to add - root is forbidden - e.g. "user1 user2 user3"
NEW_USERS=" "
# New port for SSH
SSH_PORT=""
# Server address
SERVER_IP="$(dig +short myip.opendns.com @resolver1.opendns.com)"

if [[ $EUID -ne 0 ]]; then
  echo "${RED}This script must be run as root!" 1>&2
  echo "${RED}Use ${GREEN}sudo $0${NORMAL}"
  exit 1
fi

echo -e "${BLUE}|==========================================================|
|                                                          |
|${YELLOW}     This will install and configure some software        ${BLUE}|
|${YELLOW}               for security reasons and for               ${BLUE}|
|${YELLOW}                 an easier use of Debian                  ${BLUE}|
|                                                          |
|==========================================================|${NORMAL}"
  read -n 1 -p "Press any key to start...${NORMAL}"
  echo ""
  echo ""

LOADER() {
    sleep 1
    echo -ne "${RED}[ + + +             ] 3s \r"
    sleep 0.5
    echo -ne "${YELLOW}[ + + + + + +       ] 2s \r"
    sleep 0.5
    echo -ne "${GREEN}[ + + + + + + + + + ] 1s \r${NORMAL}"
    sleep 0.5
}

if [ -z "${MONITORING}" ]; then read -p "${YELLOW}Enter the mail adresse to receive monitoring alert (Default: root@localhost): ${WHITE}" MONITORING; fi
# if [ -z "${NEW_USERS}" ]; then echo "${GREEN}Add some users to the machine - Leave empty if there is no new user"; read -p "${YELLOW}Enter new user(s): ${WHITE}" NEW_USERS; fi
if [ -z "${MONITORING}" ]; then MONITORING="root@localhost"; fi
if [ -z "${SSH_USERS}" ]; then echo -n "${RED}"; echo '/!\ BE CAREFUL - you NEED at least one user to connect with ssh on a distant machine. Leaving empty will block ssh' ; read -p "${YELLOW}Enter user(s) who can connect with ssh: ${WHITE}" SSH_USERS; fi
if [ -z "${SUDO_USERS}" ]; then read -p "${YELLOW}Enter the users who can connect with administrative rights (sudo) - ${RED}ALL ${YELLOW}rights granted: ${WHITE}" SUDO_USERS; fi
# Public Interface
VALID_IF="$(ip a | grep '^[0-9]:' | grep -v 'lo' | awk '{ print $2 }' | sed 's/://g' | tr '\n' ' ')"
if [ -z "${PUB_IF}" -a "$(ip a | grep ": <" | grep -v "lo" | cut -d: -f2 | wc -l)" != "1" ]; then while [ -z $i ]; do read -p "${YELLOW}Enter the interface to use as public interface - the one to connect to internet - ( ${VALID_IF}): ${WHITE}" PUB_IF; [ ! -z ${PUB_IF} ] && { for if in ${VALID_IF}; do [ "${if}" = ${PUB_IF} ] && { i=1; break; }; done; } done; else PUB_IF="${VALID_IF}"; fi
# Working directory
DIR=`pwd`
# Install OpenVZ
while [ "${OPENVZ}" != "y" -a "${OPENVZ}" != "Y" -a "${OPENVZ}" != "n" -a "${OPENVZ}" != "N" ]; do read -p "${YELLOW}Do you want to install openvz (y/N)?${NORMAL} " OPENVZ; done
[ "${OPENVZ}" == "y" -o "${OPENVZ}" == "Y" ] && { DEB='wheezy'; }
while [ "${FIREWALL}" != "y" -a "${FIREWALL}" != "Y" -a "${FIREWALL}" != "n" -a "${FIREWALL}" != "N" ]; do read -p "${YELLOW}Do you want to install a firewall (y/N)?${NORMAL} " FIREWALL; done

##################
#### PACKAGES ####
##################
LOADER; echo "${GREEN}Updating...             ${NORMAL}"
apt-get -qq update > /dev/null 2>&1
LOADER; echo "${GREEN}Installing etckeeper and rkhunter, this might take a while${NORMAL}"
apt-get install -qqy rkhunter libwww-perl etckeeper  > /dev/null
cd /etc
git config --global user.name "${USER}"
git config --global user.email ${USER}@$(hostname -f)
git commit --amend --reset-author -m "Initial commit" > /dev/null
LOADER; echo "${GREEN}Updating and Upgrading system with new sources.list, this might take a while${NORMAL}"
cp /etc/apt/sources.list{,.sav`date +%d-%m-%y_%T`}
[ -z ${DEB} ] && { DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1); if [ ${DEBIAN_VERSION} == 8 ]; then DEB=jessie; elif [ ${DEBIAN_VERSION} == 7 ]; then DEB=wheezy; else DEB=stable; fi; }
[ -f /etc/apt/sources.list.d/pve-enterprise.list ] && { echo "deb http://download.proxmox.com/debian ${DEB} pve-no-subscription" > /etc/apt/sources.list.d/pve-install-repo.list; rm /etc/apt/sources.list.d/pve-enterprise.list; }
echo "# Official repository
deb http://ftp.fr.debian.org/debian ${DEB} main contrib non-free
deb-src http://ftp.fr.debian.org/debian ${DEB} main contrib non-free

# Updates repository
deb http://ftp.debian.org/debian/ ${DEB}-updates main contrib non-free
deb-src http://ftp.debian.org/debian/ ${DEB}-updates main contrib non-free

# Security repository
deb http://security.debian.org/ ${DEB}/updates main contrib non-free
deb-src http://security.debian.org/ ${DEB}/updates main contrib non-free

# Backports repository
deb http://ftp.fr.debian.org/debian/ ${DEB}-backports main contrib
" > /etc/apt/sources.list
apt-get update -qq
apt-get upgrade -qqy
LOADER; echo "${GREEN}Installing packages, this might take a while${NORMAL}"
apt-get -qqy install auditd debsums dnsutils colordiff git htop libpam-cracklib locales locate most openssl selinux-basics selinux-utils sudo subversion vim > /dev/null
apt-get install -qqy portsentry 
apt-get autoremove -qqy
updatedb

####################
#### USERS CONF ####
####################
LOADER; echo "${GREEN}Adding new users if needed${NORMAL}"
for user in $(echo ${NEW_USERS} ${SSH_USERS} ${SUDO_USERS} | tr ' ' '\n' | sort | uniq | tr '\n' ' '); do
  getent passwd $user > /dev/null || { useradd -m -s /bin/bash $user; }
done
LOADER; echo "${GREEN}Modifying password for all users for better security${NORMAL}"
for user in $(cat /etc/passwd | grep /bin/bash | cut -d: -f1 | tr '\n' ' '); do
  unset PASSWD
  while [ -z "$PASSWD" ]; do read -p "${YELLOW}  - Wich password use for ${user} : ${WHITE}" PASSWD; done
	chpasswd -c SHA512 -s 200000 <<<"${user}:${PASSWD}"
done
for user in $(echo ${SUDO_USERS} | tr ' ' '\n' | sort | uniq | tr '\n' ' '); do
  echo "${user}    ALL=(ALL) ALL" >> /etc/sudoers
done
cat <<\EOF > /etc/bash_completion.d/iptdelhttp
_iptdelhttp() {
  list=''
  local choix #mot_courant
  case "$COMP_CWORD" in
    *) [ ! -z "$list" ] && { choix="$list"; } ;;
  esac
  # création de la liste finale de choix
  # mot_courant=${COMP_WORDS[COMP_CWORD]}
  COMPREPLY=( $( compgen -W '$choix' -- $mot_courant  ) )
}

complete -F _iptdelhttp iptdelhttp
EOF
source /etc/bash_completion.d/iptdelhttp
cat <<\EOF > /etc/bash_completion.d/iptdelpack
_iptdelpack() {
  list=''
  local choix mot_courant
  case "$COMP_CWORD" in
    *) [ ! -z "$list" ] && { choix="$list"; } ;;
  esac
  # création de la liste finale de choix
  mot_courant=${COMP_WORDS[COMP_CWORD]}
  COMPREPLY=( $( compgen -W '$choix' -- $mot_courant  ) )
}

complete -F _iptdelpack iptdelpack
EOF
source /etc/bash_completion.d/iptdelpack
sed -i "s/PUB_IF/${PUB_IF}/g" ${DIR}/files/.bashrc
sed -i "s/SERVER_IP/${SERVER_IP}/g" ${DIR}/files/.bashrc
cp -f ${DIR}/files/.bashrc /root/
cp -f ${DIR}/files/.bashrc /etc/skel/
for user in $(cat /etc/passwd | grep /bin/bash | cut -d: -f1 | grep -v "root" | tr '\n' ' '); do
  cp -f ${DIR}/files/.bashrc /home/$user/.bashrc
  chown $user:$user /home/$user/.bashrc
done
source ~/.bashrc

##############
#### CONF ####
##############
#### Most ####
LOADER; echo "${GREEN}Configure most and vim      ${NORMAL}"
update-alternatives --config pager > /dev/null << EOF
3
EOF
#### Vim setup ####
sed -i "s@\"syntax on@syntax on@g" /etc/vim/vimrc
sed -i "s@\"set ignorecase@set ignorecase@g" /etc/vim/vimrc
sed -i "s@\"set background=dark@set background=dark@g" /etc/vim/vimrc
echo 'set number
set expandtab
set tabstop=4' >> /etc/vim/vimrc
#### Crontab ####
update-alternatives --config editor > /dev/null << EOF
2
EOF
#### VM ####
[ $(uname -r | grep pve) ] && { sed -i 's/IPTABLES=/IPTABLES="ipt_REJECT ipt_recent ipt_owner ipt_REDIRECT ipt_tos ipt_TOS ipt_LOG ip_conntrack ipt_limit ipt_multiport iptable_filter iptable_mangle ipt_TCPMSS ipt_tcpmss ipt_ttl ipt_length ipt_state iptable_nat ip_nat_ftp" ##/' 


#################
### SECURITY ####
#################
LOADER; echo "${GREEN}Configuring ssh service          ${NORMAL}"
## SSH ##
[ -f /tmp/list ] && rm /tmp/list
until [ $([ -f /tmp/list ] && cat /tmp/list | sort | uniq | wc -l || echo 0) == 1 ]; do
  [ -f /tmp/list ] && rm /tmp/list
  read -p "${YELLOW}  - Enter the new ssh port (Default: 22): ${WHITE}" SSH_PORT
  if [ -z ${SSH_PORT} ]; then SSH_PORT=22; [ -f /tmp/list ] && rm /tmp/list; break; fi
  if [ ! -z ${SSH_PORT} -a "${SSH_PORT}" == "22" ]; then [ -f /tmp/list ] && rm /tmp/list; break; fi
  for i in $(cat /etc/services | grep -v "^#" | awk '{print $2}' | cut -d/ -f1| sort -n | uniq | tr '\n' ' '); do
    if [ ${SSH_PORT} == $i ]; then
      echo "${RED}Port ${SSH_PORT} is already used. Please enter a new one${NORMAL}"
      echo ko >> /tmp/list
    else
      echo ok >> /tmp/list
    fi
  done
done
LOADER; echo "${GREEN}  - Use port ${SSH_PORT}            ${NORMAL}"
sed -i "s/Port 22/Port ${SSH_PORT}/g" /etc/ssh/sshd_config
for user in $(echo ${SSH_USERS} | tr ' ' '\n' | sort | uniq | tr '\n' ' '); do
  mkdir -p /home/$user/.ssh
  while [ "${KEY}" != "y" -a "${KEY}" != "Y" -a "${KEY}" != "n" -a "${KEY}" != "N" ]; do read -p "${YELLOW}Do you already have a ssh key for $user (y/N): ${WHITE}" KEY; done
  if [ -z "$KEY" -o "$KEY" == "n" -o "$KEY" == "N" ]; then
    echo "${RED}Please create a couple of key for $user.
On Linux, use 'ssh-keygen -t rsa -b 3072'.
On windows, use puttygen software."
    sleep 2s
    read -p "${YELLOW}Please enter the public key created. It should look like this: ssh-rsa xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx USER
Enter the key: ${WHITE}" KEYFILE
  elif [ "$KEY" == y -o "$KEY" == "Y" ]; then
    read -p "${YELLOW}Enter the key: ${WHITE}" KEYFILE
  fi
  echo "$KEYFILE" >> /home/$user/.ssh/authorized_keys
done
LOADER && echo -n "${GREEN}  - Configure SSH to only accept choosen users:" && [ -z "$SSH_USERS" ] && { echo "-none- ${NORMAL}"; } || { echo " $SSH_USERS ${NORMAL}"; }
echo "AllowUsers ${SSH_USERS}" >> /etc/ssh/sshd_config
[ ! -z ${SSH_USERS} ] && LOADER && echo "${GREEN}  - Configure SSH users to use private/public keys instead of passwords to connect with ssh${NORMAL}"
LOADER; echo "${GREEN}  - Do NOT permit root login${NORMAL}"
sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/PermitRootLogin without-password/PermitRootLogin no/g" /etc/ssh/sshd_config
sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config
LOADER; echo "${GREEN}  - Configure ssh to use authorized_keys${NORMAL}"
sed -i "s/#AuthorizedKeysFile/AuthorizedKeysFile/g" /etc/ssh/sshd_config
LOADER; echo "${GREEN}  - Do NOT permit password login${NORMAL}"
sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
chmod -R 600 /etc/ssh
service ssh restart
## ROOT LOGIN ##
LOADER; echo "${GREEN}Mail ${MONITORING} when root login"
echo "echo \"Accès Shell Root le \" \`date\` \`who\` | mail -s \`hostname\` Shell Root de \`who | cut -d\"(\" -f2 | cut -d\")\" -f1\` ${MONITORING}" >> /root/.bashrc
## ROOTKITS DETECTION ##
sleep 3s
dpkg-reconfigure rkhunter
sed -i "s/REPORT_EMAIL=\"root\"/REPORT_EMAIL=\"${MONITORING}\"/g" /etc/default/rkhunter
## PORT SCANNING ##
LOADER; echo "${GREEN}Configure portsentry - a port scanner blocker${NORMAL}"
cp /etc/portsentry/portsentry.conf{,.sav`date +%d-%m-%y_%T`}
sed -i "s/BLOCK_UDP=\"0\"/BLOCK_UDP=\"1\"/g" /etc/portsentry/portsentry.conf
sed -i "s/BLOCK_TCP=\"0\"/BLOCK_TCP=\"1\"/g" /etc/portsentry/portsentry.conf
sed -i "s/#KILL_ROUTE=\"\/sbin\/iptables -I INPUT -s \$TARGET$ -j DROP\"/KILL_ROUTE=\"\/sbin\/iptables -I INPUT -s \$TARGET$ -j DROP/g" /etc/portsentry/portsentry.conf
sed -i "s/#KILL_RUN_CMD=\"\/some\/path\/here\/script \$TARGET\$ \$PORT\$ \$MODE\$\"/KILL_RUN_CMD=\"echo \"Blocage scan de port  \$TARGET\$\" | mail -s \"scan port ban \$TARGET\$\" $MONITORING\"/g" /etc/portsentry/portsentry.conf
## PERMISSIONS FOR COMPILERS AND INSTALLERS ##
LOADER; echo "${GREEN}Only allow compilers and installers to root${NORMAL}"
[ -f /usr/bin/gcc ] && chmod 700 /usr/bin/gcc && chmod 700 /usr/bin/gcc-4*
[ -f /usr/bin/make ] && chmod 700 /usr/bin/make
[ -f /usr/bin/aptitude ] && chmod 700 /usr/bin/aptitude
[ -f /usr/bin/dpkg ] && chmod 700 /usr/bin/dpkg
[ -f /usr/bin/apt-get ] && chmod 700 /usr/bin/apt-get
## DAILY UPDATES ##
LOADER; echo "${GREEN}Crontab to daily update and upgrade${NORMAL}"
echo '#!/bin/bash
echo "UPDATE:";
apt-get -qq update;
echo "UPGRADE:";
apt-get -qy upgrade;
echo "AUTOREMOVE:";
apt-get -y autoremove' > /etc/cron.daily/upgrade_package
chmod +x /etc/cron.daily/upgrade_package
## SECURITIES ISSUES ##
LOADER; echo "${GREEN}Prevent some security issues${NORMAL}"
sed -i "s/022/027/g" /etc/login.defs
sed -i "s/umask 022/umask 027/g" /etc/init.d/rc
[ "$(cat /etc/fstab | grep /tmp)" ] && sed -i 's@/tmp            ext4    defaults@/tmp            ext4    defaults,noexec,nosuid,nodev@g' /etc/fstab && mount -oremount /tmp
[ "$(cat /etc/fstab | grep /shm)" ] && mount -oremount /dev/shm
[ -f /etc/bind/named.conf.options ] && sed -i "20i\version \"none\";" /etc/bind/named.conf.options
[ -f /etc/motd ] && echo "------------------------------------------------------------
WARNING: You must have specific authorization to access this
machine. Unauthorized users will be logged, monitored, and
could be pursued.
------------------------------------------------------------" > /etc/motd
[ -f /etc/issue ] && echo "------------------------------------------------------------
WARNING: You must have specific authorization to access this
machine. Unauthorized users will be logged, monitored, and
could be pursued.
------------------------------------------------------------" > /etc/issue
[ -f /etc/issue.net ] && echo "------------------------------------------------------------
WARNING: You must have specific authorization to access this
machine. Unauthorized users will be logged, monitored, and
could be pursued.
------------------------------------------------------------" > /etc/issue.net
echo "none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
source ~/.bashrc
sleep 3s
cd ${DIR}/files/
[ "${OPENVZ}" == "y" -o "${OPENVZ}" == "Y" ] && { echo -e "\n${GREEN}Done! \n Press [ENTER] to continue and install OpenVZ, [CTRL +C] to leave"; chmod +x openvz.bash && ./openvz.bash; }
[ "${FIREWALL}" == "y" -o "${FIREWALL}" == "Y" ] && { echo -e "\n${GREEN}Done! \n Press [ENTER] to continue and install a firewall, [CTRL +C] to leave"; read; chmod +x firewall.bash; ./firewall.bash ${SSH_PORT} ${PUB_IF}; }
echo -e "\n${GREEN}Done!
Press [ENTER] to continue and REBOOT"
read
reboot