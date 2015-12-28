#!/bin/bash
# Template_scripts.sh
# Aurélien Partonnaud - 2015
# Free to use on a Debian 8
# Tested on a minimal Debian 64bits
clear

# Formatting variables
NORMAL=$(tput sgr0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)

if [[ $EUID -ne 0 ]]; then
  echo "${RED}This script must be run as root!" 1>&2
  echo "${RED}Use ${GREEN}sudo $0${NORMAL}"
  exit 1
fi

echo -e "${BLUE}|====================================|
|                                    |
|    ${YELLOW}This will configure proxmox${BLUE}    |
|                                    |
|====================================|${NORMAL}"
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


source ~/.bashrc
echo "${GREEN}Downloading VZ templates, this might take up to 5 minutes depending of your connection${RED}"
iptaddhttp download.openvz.org
wget -qP /var/lib/vz/template/cache/ http://download.openvz.org/template/precreated/debian-7.0-x86-minimal.tar.gz \
http://download.openvz.org/template/precreated/debian-7.0-x86.tar.gz \
http://download.openvz.org/template/precreated/debian-7.0-x86_64-minimal.tar.gz \
http://download.openvz.org/template/precreated/debian-7.0-x86_64.tar.gz \
http://download.openvz.org/template/precreated/debian-8.0-x86_64-minimal.tar.gz \
http://download.openvz.org/template/precreated/debian-8.0-x86_64.tar.gz
iptdelhttp download.openvz.org

echo "${GREEN}Configure /etc/vz/vz.conf${RED}"
LOADER
sed -i '36i\DEF_OSTEMPLATE="debian-8.0-x86_64-minimal"\nCONFIGFILE="basic"' /etc/vz/vz.conf
cp ve-basic.conf-sample /etc/vz/conf/
sed -i 's/^IPTABLES=/OLDIPTABLES=/' /etc/vz/vz.conf
sed -i '/^OLDIPTABLES/i\IPTABLES="iptable_filter iptable_mangle ipt_limit ipt_multiport ipt_tos ipt_TOS ipt_REJECT ipt_TCPMSS ipt_tcpmss ipt_ttl ipt_LOG ipt_length ip_conntrack ip_conntrack_ftp ip_conntrack_irc ipt_conntrack ipt_state ipt_helper iptable_nat ip_nat_ftp ip_nat_irc ipt_REDIRECT xt_mac ipt_owner"' /etc/vz/vz.conf
sed -i '/^OLDIPTABLES=/d' /etc/vz/vz.conf;

echo "${GREEN}Add new bridge for private network - 192.168.0.0/24${RED}"
LOADER
brctl addbr vmbr1 
echo 'auto vmbr1
iface vmbr1 inet static
        address  192.168.0.1
        netmask  255.255.255.0
        bridge_ports none
        bridge_stp off
        bridge_fd 0
' >> /etc/network/interfaces;

echo "${GREEN}Configure pve web ui not to display warning message${RED}"
LOADER
cp /usr/share/pve-manager/ext4/pvemanagerlib.js /usr/share/pve-manager/ext4/pvemanagerlib.js.sav
sed "s@data.status !== 'Active'@false@" /usr/share/pve-manager/ext4/pvemanagerlib.js

echo "${GREEN}Add ctcreate command to auto create a container${RED}"
LOADER
cat <<\EOF > /usr/sbin/ctcreate
#!/bin/bash
function ct_id () {
  unset RESULT;
  for i in $(vzlist -a -o ctid | grep "^[ [:digit:] ]*$" | tr '\n' ' '); do
    if [ "${CTID}" == "$i" ]; then RESULT="${CTID}"; fi;
  done;
}

CTID=$1
TEMPLATE=$2

[ -z $(echo ${CTID} | grep "^[ [:digit:] ]*$") ] && { RESULT=1; CTID=99; until [ -z "${RESULT}" ]; do CTID=$((CTID+1)); ct_id; done; }
read -p 'Enter the hostname of the CT - e.g. mysql.domain.tld: ' HOSTNAME
NAME=$(echo $HOSTNAME | cut -d. -f1)
read -p "Enter the root password for CT ${NAME}: " PASSWD
while [ -z "$(echo ${DISKSPACE} | grep "^[ [:digit:] ]*$")" ]; do read -p 'Enter the diskspace of the VM (in GB, default is 2GB): ' DISKSPACE; [ -z ${DISKSPACE} ] && { DISKSPACE=2; }; done
NAMESERVER=$(cat /etc/resolv.conf | sed 's/^/--/g' | tr '\n' ' ')
echo -e "Do you want to use a special template? You can use \n$(ls /var/lib/vz/template/cache/ | sed 's/\.tar\.gz$//g')\nDefault is debian-8.0-x86_64-minimal"
read TEMPLATE
[ -z ${TEMPLATE} ] && { vzctl create ${CTID}; } || { vzctl create ${CTID} --ostemplate ${TEMPLATE}; }
vzctl set ${CTID} --onboot yes --save
vzctl set ${CTID} --hostname ${HOSTNAME} --save
vzctl set ${CTID} --name ${NAME} --save
vzctl set ${CTID} --description "Container ${CTID} - ${HOSTNAME}" --save
vzctl set ${CTID} --ipadd "192.168.0.${CTID}" --save
vzctl set ${CTID} ${NAMESERVER} --save
vzctl set ${CTID} --userpasswd root:${PASSWD}
vzctl set ${CTID} --diskspace="${DISKSPACE}G:$(($DISKSPACE*1024+500))M" --save
EOF
chmod +x /usr/sbin/ctcreate
