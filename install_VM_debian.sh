# !/bin/bash
# install_VM_debian.sh
# Aurélien Partonnaud - 2015
# Free to use on a Debian 7/8
# Tested on a minimal Debian 7/8 64bits
clear

if [[ $EUID -ne 0 ]]; then
  echo "${RED}This script must be run as root!" 1>&2
  echo "${RED}Use ${GREEN}sudo $0${NORMAL}"
  exit 1
fi

#### FORMATTING VARIABLES ####
NORMAL=$(tput sgr0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
WHITE=$(tput setaf 7)
DIR=$(pwd)

SERVER_IP=$(ip a | grep 'scope global' | cut -d' ' -f6 | cut -d'/' -f1)
PUB_IF="venet0"

#### SETUP ####
echo "${GREEN}Installing packages, this might take a while${NORMAL}"
apt-get -qq update; apt-get install -qqy apt-utils apt-transport-https whiptail > /dev/null ; apt-get -qqy dist-upgrade > /dev/null
cp /etc/apt/sources.list{,.sav`date +%d-%m-%y_%T`}
[ -z ${DEB} ] && { DEBIAN_VERSION=$(cat /etc/debian_version | cut -d. -f1); if [ ${DEBIAN_VERSION} == 8 ]; then DEB=jessie; elif [ ${DEBIAN_VERSION} == 7 ]; then DEB=wheezy; else DEB=stable; fi; }
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
apt-get install -qqy apt-utils dnsutils git locales locate logwatch man-db most openssl selinux-basics selinux-utils sudo vim cron wget screen unzip zip > /dev/null
apt-get autoremove -qqy
updatedb
#### CONFIG ####
# logwatch
cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/logwatch.conf
mkdir /var/cache/logwatch/
sed -i 's/Output = stdout/Output = file/g' /etc/logwatch/conf/logwatch.conf
sed -i "s/MailFrom = Logwatch/MailFrom = Logwatch_VM_$(ip a s venet0 | grep '192.168.0.' | cut -d' ' -f 8 | cut -d'.' -f4)/g" /etc/logwatch/conf/logwatch.conf
sed -i 's@#Filename = /tmp/logwatch@Filename = /var/log/logwatch@g' /etc/logwatch/conf/logwatch.conf
sed -i 's@Range = yesterday@Range = yesterday@g' /etc/logwatch/conf/logwatch.conf
sed -i 's/Detail = Low/Detail = 7/g' /etc/logwatch/conf/logwatch.conf
cat << EOF > /etc/cron.daily/00logwatch
#!/bin/bash
#Check if removed-but-not-purged
test -x /usr/share/logwatch/scripts/logwatch.pl || { echo "ERROR: /usr/share/logwatch/scripts/logwatch.pl not found"}
#execute
/usr/sbin/logwatch
/usr/sbin/logwatch --mailto ${MONITORING_MAIL}
#Note: It's possible to force the recipient in above command
#Just pass --mailto address@a.com instead of --output mail
EOF
# daily updates
echo "${GREEN}config daily updates${NORMAL}"
echo '#!/bin/bash
echo "UPDATE:";
apt-get -qq update;
echo "UPGRADE:";
apt-get -qy upgrade;
echo "AUTOREMOVE:";
apt-get -y autoremove' > /etc/cron.daily/upgrade_package
chmod +x /etc/cron.daily/upgrade_package
# pager
echo "${GREEN}Config pager, editor, vim and most${NORMAL}"
update-alternatives --config pager > /dev/null << EOF
3
EOF
# editor/vim
sed -i "s@\"syntax on@syntax on@g" /etc/vim/vimrc
sed -i "s@\"set ignorecase@set ignorecase@g" /etc/vim/vimrc
sed -i "s@\"set background=dark@set background=dark@g" /etc/vim/vimrc
echo 'set number
set expandtab
set tabstop=4' >> /etc/vim/vimrc
update-alternatives --config editor > /dev/null << EOF
2
EOF
# security
echo "${GREEN}Check for security issues${NORMAL}"
[ -f /usr/bin/gcc ] && chmod 700 /usr/bin/gcc && chmod 700 /usr/bin/gcc-4*
[ -f /usr/bin/make ] && chmod 700 /usr/bin/make
[ -f /usr/bin/aptitude ] && chmod 700 /usr/bin/aptitude
[ -f /usr/bin/dpkg ] && chmod 700 /usr/bin/dpkg
[ -f /usr/bin/apt-get ] && chmod 700 /usr/bin/apt-get
sed -i "s/022/027/g" /etc/login.defs
sed -i "s/umask 022/umask 027/g" /etc/init.d/rc
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
echo "${GREEN}Else...${NORMAL}"
# .bashrc 
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
sed -i "s/PUB_IF/${PUB_IF}/g" ${DIR}/files/.bashrc_VM_debian
sed -i "s/SERVER_IP/${SERVER_IP}/g" ${DIR}/files/.bashrc_VM_debian
cp -f ${DIR}/files/.bashrc_VM_debian /root/.bashrc
cp -f ${DIR}/files/.bashrc_VM_debian /etc/skel/.bashrc
for user in $(cat /etc/passwd | grep /bin/bash | cut -d: -f1 | grep -v "root" | tr '\n' ' '); do
  cp -f ${DIR}/files/.bashrc_VM_debian /home/$user/.bashrc
  chown $user:$user /home/$user/.bashrc
done
cd ${DIR}/files/
chmod +x *VM*
./firewall_VM_debian.sh

