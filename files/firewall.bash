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
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)

if [[ $EUID -ne 0 ]]; then
  echo "${RED}This script must be run as root!" 1>&2
  echo "${RED}Use ${GREEN}sudo $0${NORMAL}"
  exit 1
fi

echo -e "${BLUE}|====================================|
|                                    |
|     ${YELLOW}This will install iptables${BLUE}     |
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

###################
#### VARIABLES ####
###################
IPT='/sbin/iptables'
# Default=22
SSH_PORT="${1}"
# Only these PUBLIC ip address could connect with ssh - Empty if none
PUB_SSH_ONLY=''
# public interface - Default is eth0
PUB_IF="${2}"
# vpn / private net - Empty if none
VPN_IF=''
# Public address of the server - Leave empty if you don't know what you're doing
SERVER_IP=''
# DNS SERVER - List of DNS servers to reach - DNS in resolv.conf will be automatically added 
DNS_SERVER='resolver1.opendns.com'
# Allow connections to package servers - Leave empty if you don't know what you're doing
PACKAGE_SERVER=''
# Site we accept to connect to
# sourceforge.net: heanet.dl.sourceforge.net netix.dl.sourceforge.net downloads.sourceforge.net skylink.dl.sourceforge.net netcologne.dl.sourceforge.net sourceforge.net
# debian.org: cdimage.debian.org saimei.acc.umu.se gemmei.acc.umu.se
# Others examples: pgp.mit.edu github.com
WEBSITE=''
# Countries that shouldn't access the server - All except France(FR)
BLOCKED_COUNTRIES='A1 A2 AD AE AF AG AI AL AM AO AP AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG ER ES ET EU FI FJ FK FM FO GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'
# IP That shouldn't be on the internet [DO NOT TOUCH]
SPOOF_IP='0.0.0.0/8 10.0.0.0/8 169.254.0.0/16 127.0.0.0/8 168.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3 192.168.0.0/24 255.255.255.255/32'
# Loopback [DO NOT TOUCH]
LO_IF='lo'





#####################################
#### FLUSH ALL FOR CLEAN INSTALL ####
#####################################
LOADER
echo "${GREEN}Flush all and restore to default for clean install${RED}"
${IPT} -P INPUT ACCEPT
${IPT} -P FORWARD ACCEPT
${IPT} -P OUTPUT ACCEPT
${IPT} -F
${IPT} -X
${IPT} -t nat -P PREROUTING ACCEPT
${IPT} -t nat -P POSTROUTING ACCEPT
${IPT} -t nat -P OUTPUT ACCEPT
${IPT} -t nat -F
${IPT} -t nat -X
${IPT} -t mangle -F
${IPT} -t mangle -X





# Fill empty variables [DO NOT TOUCH]
## PUB_IF
VALID_IF="$(ip a | grep '^[0-9]:' | grep -v 'lo' | awk '{ print $2 }' | sed 's/://g' | tr '\n' ' ')"
if [ -z "${PUB_IF}" -a "$(ip a | grep ": <" | grep -v "lo" | cut -d: -f2 | wc -l)" != "1" ]; then if [ -z "${PUB_IF}"] ; then while [ -z $i ]; do read -p "${YELLOW}Enter the interface to use as public interface - the one to connect to internet - ( ${VALID_IF}): ${WHITE}" PUB_IF; [ ! -z ${PUB_IF} ] && { for if in ${VALID_IF}; do [ "${if}" = ${PUB_IF} ] && { i=1; break; }; done; }; done; fi; elif [ -z "${PUB_IF}" ]; then   PUB_IF="${VALID_IF}"; fi
## SERVER_IP
if [ -z "${SERVER_IP}" ]; then SERVER_IP="$(dig +short myip.opendns.com @resolver1.opendns.com)"; fi
## DNS_SERVER
DNS_SERVER="$(cat /etc/resolv.conf | grep -v 127.0 | grep nameserver | cut -d" " -f 2 | awk -v ORS=" " '{ print $1 }') $(echo $DNS_SERVER )"
## PACKAGE_SERVER
if [ -z "${PACKAGE_SERVER}" ]; then PACKAGE_SERVER="$(cat /etc/apt/sources.list | grep -v "^#" | cut -d" " -f2 | cut -d"/" -f3 | sort | uniq | awk -v ORS=" " '{ print $1 }') $([ "$(ls -A /etc/apt/sources.list.d)" ] && cat /etc/apt/sources.list.d/* | grep -v "^#" | cut -d" " -f2 | cut -d"/" -f3 | sort | uniq | awk -v ORS=" " '{ print $1 }')"; fi
# SSH PORT
function sshport () { 
  unset RESULT; 
  for i in $(cat /etc/services | grep -v "^#" | awk '{print $2}' | cut -d/ -f1| sort -n | uniq | tr '\n' ' '); do   
    if [ "${SSH_PORT}" == "$i" ]; then RESULT="${SSH_PORT}"; fi; 
  done; 
}

RESULT=1;
[ -z "$(echo ${SSH_PORT} | grep "^[ [:digit:] ]*$")" ] && { while [ -z "$(echo $SSH_PORT | grep "^[ [:digit:] ]*$")" ]; do read -p "${YELLOW}Enter the new ssh port (Default: 22): ${WHITE}" SSH_PORT; done; sshport; }
while [ ! -z "${RESULT}" -a "${SSH_PORT}" != 22 ]; do
  unset SSH_PORT
  while [ -z "$(echo ${SSH_PORT} | grep "^[ [:digit:] ]*$")" ]; do
    read -p "${RED}Port ${SSH_PORT} is not a usable port. Please enter a new one: ${NORMAL}" SSH_PORT; 
  done
  sshport
done



################################################
#### INSTALLING IPTABLES AND XTABLES-ADDONS ####
################################################
sleep 1
echo "${GREEN}Installing packages, this might take a while${NORMAL}"
apt-get -qq update
apt-get install -qqy iptables-dev libtext-csv-xs-perl build-essential pkg-config automake wget xz-utils unzip zip > /dev/null
[ $? != 0 ] && { echo "${RED}Error while installing packages! Please run manually this command 'apt-get install iptables-dev libtext-csv-xs-perl build-essential pkg-config automake wget xz-utils unzip zip' and see what happened"; read -p "${YELLOW}Press [ENTER] to continue when the problem is solved, [CTRL+C] to leave${WHITE}"; }
if [ ! -d /opt/src/xtables-addons ]; then
[ ! -z $(uname -r | grep pve) ] && { apt-get install -qqy pve-headers-`uname -r`; } || { apt-get install -qqy linux-headers-`uname -r`; }
[ -f /etc/selinux/config ] && { sed -i 's|SELINUX=enforcing|SELINUX=disabled|' /etc/selinux/config; }
[ ! -z $(uname -r | grep pve) ] && { sed -i "s|#define CONFIG_IP6_NF_IPTABLES_MODULE 1|/* #define CONFIG_IP6_NF_IPTABLES_MODULE 1 */|" /lib/modules/`uname -r`/build/include/linux/autoconf.h; }
  mkdir -p /opt/src && cd /opt/src
  base_url=http://sourceforge.net/projects/xtables-addons/files/Xtables-addons
  [[ "$(uname -r | cut -d. -f1-2 | tr '.' ',')" -ge "3,7" ]] && { wget -t 3 -T 30 -qO- $base_url/xtables-addons-2.10.tar.xz | tar xJv; } || { wget -t 3 -T 30 -qO- $base_url/xtables-addons-1.47.1.tar.xz | tar xJv; }
  cp -r xtables-addons-* xtables-addons
  cd xtables-addons
  ./configure && make && make install  
  depmod 
  cd geoip/
  sed -i -e 's/wget/wget -q/g' -e 's/unzip/unzip -q/g' -e 's/GeoIPv6.csv{,.gz} GeoIPCountryCSV.zip GeoIPCountryWhois.csv/GeoIP*/g' xt_geoip_dl
  ./xt_geoip_dl
  ./xt_geoip_build GeoIPCountryWhois.csv > /dev/null
  mkdir -p /usr/share/xt_geoip/
  cp -r {BE,LE} /usr/share/xt_geoip/
  echo "#!/bin/bash
# /etc/cron.weekly/update_geoip
iptables -t filter -I OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d geolite.maxmind.com -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -t filter -I INPUT -i ${PUB_IF} -p tcp -s geolite.maxmind.com -d ${SERVER_IP} -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
[ -d /opt/src/xtables-addons ] && { cd /opt/src/xtables-addons; } || { echo 'Error: /opt/src/xtables-addons/ source folder not found.'; exit 1; }
./xt_geoip_dl
[ ! -f './GeoIPCountryWhois.csv' ] && { echo 'Error: GeoIPCountryWhois.csv file not found.'; exit 1; }
[ ! -s './GeoIPCountryWhois.csv' ] && { echo 'Error: GeoIPCountryWhois.csv file is empty.'; exit 1; }
./xt_geoip_build GeoIPCountryWhois.csv > /dev/null
[ ! -d /usr/share/xt_geoip/ ] && { echo 'Be careful, /usr/share/xt_geoip/ folder was not created yet, any previous instll failed'; mkdir -p /usr/share/xt_geoip/; }
cp -rf {BE,LE} /usr/share/xt_geoip/
iptables -t filter -D OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d geolite.maxmind.com -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -t filter -D INPUT -i ${PUB_IF} -p tcp -s geolite.maxmind.com -d ${SERVER_IP} -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
" > /etc/cron.weekly/update_geoip
  chmod +x /etc/cron.weekly/update_geoip
[ ! -z $(uname -r | grep pve) ] && { sed -i "s|/\* #define CONFIG_IP6_NF_IPTABLES_MODULE 1 \*/|#define CONFIG_IP6_NF_IPTABLES_MODULE 1|" /lib/modules/`uname -r`/build/include/linux/autoconf.h; }
fi




################################
## BASIC RULES [DO NOT TOUCH] ##
################################
LOADER
echo "${GREEN}Keepalive established link${RED}"
${IPT} -t filter -I INPUT  -i ${PUB_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
${IPT} -t filter -I OUTPUT -o ${PUB_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

LOADER
echo "${GREEN}Change INPUT, OUTPUT and FORWARD POLICY to DROP${RED}"
${IPT} -t filter -P INPUT   DROP 
${IPT} -t filter -P OUTPUT  DROP
${IPT} -t filter -P FORWARD DROP

LOADER
echo "${GREEN}Allow all and everything on localhost${RED}"
${IPT} -t filter -A INPUT  -i ${LO_IF} -j ACCEPT
${IPT} -t filter -A OUTPUT -o ${LO_IF} -j ACCEPT

if [ ! -z ${VPN_IF} ]; then
 LOADER
 echo "${GREEN}Allow all through VPN${RED}"
 ${IPT} -t filter -A INPUT  -i ${VPN_IF} -j ACCEPT
 ${IPT} -t filter -A OUTPUT -o ${VPN_IF} -j ACCEPT
fi





#######################################
#### SPECIFIC RULES [DO NOT TOUCH] ####
#######################################
## DNS SERVERS
echo "${GREEN}Allow DNS lookups (tcp,udp port 53) to DNS server(s)${RED}"
${IPT} -N DNS_SERVER
for IP in ${DNS_SERVER}; do
  LOADER
	echo "${GREEN}  - Allow DNS lookups (tcp,udp port 53) to server '${IP}'${RED}"
	${IPT} -t filter -A DNS_SERVER -o ${PUB_IF} -p udp -s ${SERVER_IP} -d ${IP} --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	${IPT} -t filter -A DNS_SERVER -i ${PUB_IF} -p udp -s ${IP} -d ${SERVER_IP} --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	${IPT} -t filter -A DNS_SERVER -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	${IPT} -t filter -A DNS_SERVER -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
done
${IPT} -t filter -I INPUT  1 -j DNS_SERVER
${IPT} -t filter -I OUTPUT 1 -j DNS_SERVER

## PACKAGE SERVERS
echo "${GREEN}Allow tcp connection to packages servers${RED}"
${IPT} -N PACKAGE_SERVER
for IP in ${PACKAGE_SERVER}; do
 LOADER
 echo "${GREEN}  - Allow tcp connection to '${IP}' on port 21,80,443${RED}"
 ${IPT} -t filter -A PACKAGE_SERVER -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} -m multiport --dports 21,80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
 ${IPT} -t filter -A PACKAGE_SERVER -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} -m multiport --sports 21,80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
done
${IPT} -t filter -I INPUT  2 -i ${PUB_IF} -p tcp -j PACKAGE_SERVER
${IPT} -t filter -I OUTPUT 2 -o ${PUB_IF} -p tcp -j PACKAGE_SERVER

echo "${GREEN}Allow tcp connection to useful websites on port 21,80,443${RED}"
${IPT} -N SPECIFIC_WEBSITE
for IP in ${WEBSITE}; do
 LOADER
 echo "${GREEN}  - Allow tcp connection to '${IP}' on port 80,443${RED}"
sudo ${IPT} -t filter -A SPECIFIC_WEBSITE -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo ${IPT} -t filter -A SPECIFIC_WEBSITE -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
done
${IPT} -t filter -I INPUT  3 -i ${PUB_IF} -p tcp -j SPECIFIC_WEBSITE
${IPT} -t filter -I OUTPUT 3 -o ${PUB_IF} -p tcp -j SPECIFIC_WEBSITE

## NTP, sync
LOADER
echo "${GREEN}Allow outgoing connections to port 123 (ntp syncs)${RED}"
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p udp -s ${SERVER_IP} --dport 123 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p udp -d ${SERVER_IP} --sport 123 -m conntrack --ctstate ESTABLISHED     -j ACCEPT





###################################
## SECURITY RULES [DO NOT TOUCH] ##
###################################
LOADER
echo "${GREEN}Prevent Smurfs Packets Attack${RED}"
## The attacker in this attack sends a large number of ICMP echo broadcast packet, with source IP address spoofed to that of target's IP address. All the machines in the network recieve this broadcast message and reply to the target with echo reply packet. One way to block this attack is to block all the ICMP packets, but if that can't be done, a limit may be applied to the icmp packets allowed.
${IPT} -t filter -N ICMP_RULES
sleep 1.5
echo "${GREEN}  - Drop address-mask-request and timestamp-request ping${RED}"
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type address-mask-request -j DROP
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type timestamp-request    -j DROP
sleep 1.5
echo "${GREEN}  - Allow destination-unreachable, source-quench, time-exceeded and parameter-problem ping ${RED}"
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type destination-unreachable -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j ACCEPT
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type source-quench           -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j ACCEPT
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type time-exceeded           -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j ACCEPT
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type parameter-problem       -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j ACCEPT
sleep 1.5
echo "${GREEN}  - Allow limited incoming ping${RED}"
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type echo-request            -m state --state NEW -m limit --limit 10/s --limit-burst 1 -j ACCEPT
${IPT} -t filter -A ICMP_RULES -o ${PUB_IF} -p icmp -s ${SERVER_IP} -m icmp --icmp-type echo-reply -j ACCEPT
sleep 1.5
echo "${GREEN}  - Allow unlimited outgoming ping${RED}"
${IPT} -t filter -A ICMP_RULES -o ${PUB_IF} -p icmp -s ${SERVER_IP} -m icmp --icmp-type echo-request -j ACCEPT
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type echo-reply   -j ACCEPT
${IPT} -t filter -I INPUT  4 -j ICMP_RULES
${IPT} -t filter -I OUTPUT 4 -j ICMP_RULES

LOADER
echo "${GREEN}Log and Drop Spoof ip       ${RED}"
${IPT} -t filter -N SPOOF_IP
for IP in ${SPOOF_IP}; do
 ${IPT} -t filter -A SPOOF_IP -i ${PUB_IF} -s ${IP} -j LOG -m limit --limit 12/min --log-level 4 --log-prefix 'SPOOFED_IP '
 ${IPT} -t filter -A SPOOF_IP -i ${PUB_IF} -s ${IP} -j DROP
done
${IPT} -t filter -I INPUT   -i ${PUB_IF} -p tcp -d ${SERVER_IP} -j SPOOF_IP
${IPT} -t filter -I OUTPUT  -o ${PUB_IF} -p tcp -s ${SERVER_IP} -j SPOOF_IP

LOADER
echo "${GREEN}Log and Drop/Reject Bad tcp packets${RED}"
${IPT} -t filter -N BAD_TCP
sleep 1.5
echo "${GREEN}  - Force FRAGMENTS Packets check${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp -f -j DROP

sleep 1.5
echo "${GREEN}  - Drop INVALID packets${RED}"
${IPT} -t filter -A BAD_TCP   -m state --state INVALID -j DROP
${IPT} -t filter -A BAD_TCP -m state --state INVALID -j DROP
${IPT} -t filter -A BAD_TCP  -m state --state INVALID -j DROP

sleep 1.5
echo "${GREEN}  - Log and Drop incoming tcp packets with 0 as sport or dport${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --dport 0 -m limit --limit 6/h --limit-burst 1 -j LOG --log-prefix 'Port_0_OS_fingerprint '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --dport 0 -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p udp --dport 0 -m limit --limit 6/h --limit-burst 1 -j LOG --log-prefix 'Port 0 OS fingerprint '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p udp --dport 0 -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --sport 0 -m limit --limit 6/h --limit-burst 5 -j LOG --log-prefix 'tcp_source_port_0 '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --sport 0 -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p udp --sport 0 -m limit --limit 6/h --limit-burst 5 -j LOG --log-prefix 'udp_source_port_0 '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p udp --sport 0 -j DROP

sleep 1.5
echo "${GREEN}  - Reject New tcp packets with SYN/ACK flag${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset

sleep 1.5
echo "${GREEN}  - Log and Drop XMAS Packets${RED}"
## A christmas tree packet is a packet in which all the flags in any protocol are set. The FIN, URG and PSH bits in the -p tcp header of this kind of packet are set. This packet is called Christmas Tree packet, because all the fields of header are "lightened up" like a Christmas tree. This type of packet requires much processing than the usual packets, so the server allocates a large number of resources for this packet.
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL FIN,PSH,URG         -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix 'STEALTH_XMAS_IP '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL FIN,PSH,URG         -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix 'STEALTH_XMAS_IP '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL ALL                 -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix 'STEALTH_XMAS_IP '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL ALL                 -j DROP

sleep 1.5
echo "${GREEN}  - Log and Drop NULL Packets${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL NONE                -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix 'STEALTH_NULL_IP '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL NONE                -j DROP

sleep 1.5
echo "${GREEN}  - Log and Drop FIN Scan${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL FIN                 -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix 'STEALTH_FIN_SCAN '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL FIN                 -j DROP

sleep 1.5
echo "${GREEN}  - Log and Drop SYN/RST Scan${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN,RST         -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix 'STEALTH_SYN-RST_SCAN '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN,RST         -j DROP

sleep 1.5
echo "${GREEN}  - Log and Drop SYN/FIN Scan${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN         -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix 'STEALTH_SYN-FIN_SCAN '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN          -j DROP
${IPT} -t filter -I INPUT  2 -i ${PUB_IF} -p tcp -j BAD_TCP
${IPT} -t filter -I FORWARD -i ${PUB_IF} -p tcp -j BAD_TCP
${IPT} -t filter -I OUTPUT 2 -o ${PUB_IF} -p tcp -j BAD_TCP

LOADER
echo "${GREEN}Drop countries that shouldn't access the server${RED}"
${IPT} -N GEOIP
for IP in ${BLOCKED_COUNTRIES}; do
${IPT} -t filter -A GEOIP -m geoip --src-cc ${IP} -j DROP
done
${IPT} -t filter -I INPUT 6 -i ${PUB_IF} -p tcp -j GEOIP
${IPT} -t filter -I FORWARD -i ${PUB_IF} -p tcp -j GEOIP

LOADER
echo "${GREEN}Prevent SYN Flood Attack    ${RED}"
${IPT} -t filter -I INPUT 7 -i ${PUB_IF} -p tcp  -d ${SERVER_IP} -m state --state NEW -m tcp --syn -m recent --name synflood --set
${IPT} -t filter -I INPUT 8 -i ${PUB_IF} -p tcp  -d ${SERVER_IP} -m state --state NEW -m tcp --syn -m recent --name synflood --update --seconds 1 --hitcount 10 -j DROP





################################################
## GLOBAL IPTABLES RULES. PUT HERE YOUR RULES ##
################################################
LOADER
echo "${GREEN}Log and Allow SSH on port ${SSH_PORT}${RED}"
if [ -z ${PUB_SSH_ONLY} ]; then
sleep 1.5
echo "${GREEN}  - Log and Allow incoming SSH on port ${SSH_PORT}${RED}"
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate NEW -m recent --set --name SSH -j LOG --log-prefix 'SSH_IN '
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -m recent    --update  --seconds 60 --hitcount 2 --name SSH -j DROP
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate NEW -m recent --set --name SSH -j ACCEPT
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} --sport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix 'SSH_IN '
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} --sport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j ACCEPT
else for IP in ${PUB_SSH_ONLY}; do
sleep 1.5
echo "${GREEN}  - Log and Allow incoming SSH on port ${SSH_PORT} from '${IP}'${RED}"
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate NEW -m recent --set --name SSH -j LOG --log-prefix 'SSH_IN '
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} --dport ${SSH_PORT} -m recent    --update  --seconds 60 --hitcount 2 --name SSH -j DROP
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate NEW -m recent --set --name SSH -j ACCEPT
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} --sport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix 'SSH_IN '
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} --sport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j ACCEPT
done; fi
sleep 1.5
echo "${GREEN}  - Log and Allow outgoing SSH on port ${SSH_PORT}${RED}"
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} --sport ${SSH_PORT} -m conntrack --ctstate NEW -j LOG --log-prefix 'SSH_OUT '
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} --sport ${SSH_PORT} -m conntrack --ctstate NEW -j ACCEPT
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix 'SSH_OUT '
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j ACCEPT

LOADER
echo "${GREEN}Allow outgoing smtp connections${RED}"
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} -m multiport --dports 25,587 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} -m multiport --sports 25,587 -m conntrack --ctstate ESTABLISHED     -j ACCEPT

while [ "${WEB}" != "y" -a "${WEB}" != "Y" -a "${WEB}" != "n" -a "${WEB}" != "N" ]; do read -p "${YELLOW}Do you want to access a web server  - incoming tcp to port 80,443 (y/N)?${NORMAL} " WEB; done
if [ "${WEB}" == "y" -o "${WEB}" == "Y" ]; then
LOADER
echo "${GREEN}Allow new and established incoming connections to web ports (80, 443)${RED}"
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} -m multiport --dports 80,443 -m conntrack --ctstate NEW -m recent --set --name WEB
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} -m multiport --dports 80,443 -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount 20 --rttl --name WEB -j DROP
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -m multiport --dports 80,443 -m limit --limit 50/s --limit-burst 50 -j ACCEPT
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -d ${SERVER_IP} -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
fi

while [ "${PROXMOX}" != "y" -a "${PROXMOX}" != "Y" -a "${PROXMOX}" != "n" -a "${PROXMOX}" != "N" ]; do read -p "${YELLOW}Do you want to access Proxmox Web Interface (y/N)?${NORMAL} " PROXMOX; done
if [ "${PROXMOX}" == "y" -o "${PROXMOX}" == "Y" ]; then
 LOADER
 echo "${GREEN}  - Allow Proxmox WebUI          ${RED}"
 ${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport 8006 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
 ${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} --sport 8006 -m conntrack --ctstate ESTABLISHED     -j ACCEPT
fi

while [ "${DEDIBACKUP}" != "y" -a "${DEDIBACKUP}" != "Y" -a "${DEDIBACKUP}" != "n" -a "${DEDIBACKUP}" != "N" ]; do read -p "${YELLOW}Do you want to permit ftp save to dedibackup-dc3.online.net (y/N)?${NORMAL} " DEDIBACKUP; done
if [ "${DEDIBACKUP}" == "y" -o "${DEDIBACKUP}" == "Y" ]; then
 LOADER
 echo "${GREEN}  - Allow dedibackup-dc3.online.net${RED}"
 ${IPT} -N DEDIBACKUP
 ${IPT} -t filter -A DEDIBACKUP -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d dedibackup-dc3.online.net --dport 21 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
 ${IPT} -t filter -A DEDIBACKUP -i ${PUB_IF} -p tcp -s dedibackup-dc3.online.net -d ${SERVER_IP} --sport 21 -m conntrack --ctstate ESTABLISHED -j ACCEPT
 ${IPT} -t filter -I INPUT  5 -i ${PUB_IF} -p tcp -j DEDIBACKUP
 ${IPT} -t filter -I OUTPUT 5 -o ${PUB_IF} -p tcp -j DEDIBACKUP
fi
${IPT} -I INPUT -m psd --psd-weight-threshold 15 --psd-hi-ports-weight 3 -j DROP




###############
## NAT RULES ##
###############
if [ "$(sysctl net.ipv4.ip_forward | awk '{print $3}')" != "1" -o -z "$(cat /etc/sysctl.conf | grep "net.ipv4.ip_forward =")" ]; then
  echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
else
  sed -i 's/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf
fi
sysctl -qp /etc/sysctl.conf

#### INTER VM - OK ####
# ${IPT} -A FORWARD -s 192.168.0.0/16 -d 192.168.0.0/16 -j ACCEPT
# Redirection port HOST->VM
# ${IPT} -t nat -I PREROUTING -i ${PUB_IF} -p tcp -m tcp --sport 1024:65535 --dport 80 -j DNAT --to-destination 192.168.0.101:80
# ${IPT} -I FORWARD -i ${PUB_IF} -p tcp -d 192.168.0.101 --dport 80 -j ACCEPT
#### NAT EXTERNE - OK ####
# ${IPT} -t nat -I POSTROUTING -o ${PUB_IF} -s 192.168.0.0/16 ! -d 192.168.0.0/16 -j MASQUERADE
# A ADAPTER!!!!
# ${IPT} -I FORWARD 2 -i ${PUB_IF} -d 192.168.0.0/16 -j ACCEPT
# ${IPT} -I FORWARD 2 -o ${PUB_IF} -s 192.168.0.0/16 -j ACCEPT




##################################
## LOG AND DROP EVERYTHING ELSE ##
##################################
LOADER
echo "${GREEN}Log and Drop everything else${RED}"
${IPT} -t filter -A INPUT  -i ${PUB_IF} -j LOG -m limit --limit 5/min --log-level 4 --log-prefix 'IP_INPUT _DROP '
${IPT} -t filter -A INPUT  -i ${PUB_IF} -j DROP
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -j LOG -m limit --limit 5/min --log-level 4 --log-prefix 'IP_OUTPUT_DROP '
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -j DROP
${IPT} -t filter -A FORWARD -o ${PUB_IF} -j DROP





################################################
## SAVE RULES TO PREVENT FLUSHING FROM REBOOT ##
################################################
LOADER
echo "${GREEN}Save rules to prevent reboot flushing${RED}"
iptables-save -c > /etc/iptables.rules
echo '#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0' > /etc/network/if-pre-up.d/iptables
chmod +x /etc/network/if-pre-up.d/iptables
echo ' #!/bin/sh
iptables-save -c > /etc/iptables.rules
if [ -f /etc/iptables.rules ]; then
iptables-restore < /etc/iptables.rules
fi
exit 0' > /etc/network/if-post-down.d/iptables
chmod +x /etc/network/if-post-down.d/iptables
echo -e "\n${GREEN}Done! ${NORMAL}"
echo "${GREEN}You can open/close connections -ports 80,443- using iptaddhttp/iptdelhttp command
You can also open/close a connections -ports 21,80,443- using iptaddpack/iptdelpack command ${NORMAL}"
source ~/.bashrc
exit 0
