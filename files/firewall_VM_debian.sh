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


###################
#### VARIABLES ####
###################
IPT='/sbin/iptables'
# Default=22
SSH_PORT="22"
# Only these PUBLIC ip address could connect with ssh - Empty if none
PUB_SSH_ONLY='192.168.0.0/16'
# public interface - Default is eth0
PUB_IF="venet0"
# vpn / private net - Empty if none
VPN_IF=''
# Public address of the server - Leave empty if you don't know what you're doing
SERVER_IP=''
# DNS SERVER - List of DNS servers to reach - DNS in resolv.conf will be automatically added 
DNS_SERVER=''
SPOOF_IP='0.0.0.0/8 10.0.0.0/8 169.254.0.0/16 127.0.0.0/8 168.254.0.0/16 172.16.0.0/12 224.0.0.0/3 255.255.255.255/32'
# Allow connections to package servers - Leave empty if you don't know what you're doing
PACKAGE_SERVER=''
# Site we accept to connect to
# sourceforge.net: heanet.dl.sourceforge.net netix.dl.sourceforge.net downloads.sourceforge.net skylink.dl.sourceforge.net netcologne.dl.sourceforge.net sourceforge.net
# debian.org: cdimage.debian.org saimei.acc.umu.se gemmei.acc.umu.se
# Others examples: pgp.mit.edu github.com
WEBSITE=''
# Loopback [DO NOT TOUCH]
LO_IF='lo'


#####################################
#### FLUSH ALL FOR CLEAN INSTALL ####
#####################################
echo "${GREEN}Flush all and restore to default for clean install${RED}"
${IPT} -P INPUT ACCEPT
${IPT} -P OUTPUT ACCEPT
${IPT} -F
${IPT} -X
${IPT} -t mangle -F
${IPT} -t mangle -X


#############################################
#### FILL EMPTY VARIABLES [DO NOT TOUCH] ####
#############################################
## PUB_IF
VALID_IF="$(ip a | grep '^[0-9]:' | grep -v 'lo' | awk '{ print $2 }' | sed 's/://g' | tr '\n' ' ')"
if [ -z "${PUB_IF}" -a "$(ip a | grep ": <" | grep -v "lo" | cut -d: -f2 | wc -l)" != "1" ]; then if [ -z "${PUB_IF}"] ; then while [ -z $i ]; do read -p "${YELLOW}Enter the interface to use as public interface - the one to connect to internet - ( ${VALID_IF}): ${WHITE}" PUB_IF; [ ! -z ${PUB_IF} ] && { for if in ${VALID_IF}; do [ "${if}" = ${PUB_IF} ] && { i=1; break; }; done; }; done; fi; elif [ -z "${PUB_IF}" ]; then   PUB_IF="${VALID_IF}"; fi
## SERVER_IP
if [ -z "${SERVER_IP}" ]; then SERVER_IP="$(ifconfig | grep cast | cut -d':' -f2 | cut -d' ' -f1 | grep -v '^127')"; fi
## DNS_SERVER
DNS_SERVER="$(cat /etc/resolv.conf | grep -v 127.0 | grep nameserver | cut -d" " -f 2 | awk -v ORS=" " '{ print $1 }') $(echo $DNS_SERVER )"
## PACKAGE_SERVER
if [ -z "${PACKAGE_SERVER}" ]; then PACKAGE_SERVER="$(cat /etc/apt/sources.list | grep -v "^#" | cut -d" " -f2 | cut -d"/" -f3 | sort | uniq | awk -v ORS=" " '{ print $1 }') $([ "$(ls -A /etc/apt/sources.list.d)" ] && cat /etc/apt/sources.list.d/* | grep -v "^#" | cut -d" " -f2 | cut -d"/" -f3 | sort | uniq | awk -v ORS=" " '{ print $1 }')"; fi


################################################
#### INSTALLING IPTABLES ANS XTABLES-ADDONS ####
################################################
echo "${GREEN}Installing packages, this might take a while${NORMAL}"
apt-get -qq update
apt-get install -qqy iptables-dev libtext-csv-xs-perl build-essential pkg-config automake wget xz-utils unzip zip dnsutils > /dev/null


################################
## BASIC RULES [DO NOT TOUCH] ##
################################
echo "${GREEN}Keepalive established link${RED}"
${IPT} -t filter -I INPUT  -i ${PUB_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
${IPT} -t filter -I OUTPUT -o ${PUB_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

echo "${GREEN}Change INPUT, OUTPUT and FORWARD POLICY to DROP${RED}"
${IPT} -t filter -P INPUT   DROP 
${IPT} -t filter -P OUTPUT  DROP
${IPT} -t filter -P FORWARD DROP

echo "${GREEN}Allow all and everything on localhost${RED}"
${IPT} -t filter -A INPUT  -i ${LO_IF} -j ACCEPT
${IPT} -t filter -A OUTPUT -o ${LO_IF} -j ACCEPT

#######################################
#### SPECIFIC RULES [DO NOT TOUCH] ####
#######################################
## DNS SERVERS
echo "${GREEN}Allow DNS lookups (tcp,udp port 53) to DNS server(s)${RED}"
${IPT} -N DNS_SERVER
for IP in ${DNS_SERVER}; do
	${IPT} -t filter -A DNS_SERVER -o ${PUB_IF} -p udp -s ${SERVER_IP} -d ${IP} --dport 53 -j ACCEPT
	${IPT} -t filter -A DNS_SERVER -i ${PUB_IF} -p udp -s ${IP} -d ${SERVER_IP} --sport 53 -j ACCEPT
	${IPT} -t filter -A DNS_SERVER -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} --dport 53 -j ACCEPT
	${IPT} -t filter -A DNS_SERVER -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} --sport 53 -j ACCEPT
done
${IPT} -t filter -I INPUT  1 -j DNS_SERVER
${IPT} -t filter -I OUTPUT 1 -j DNS_SERVER

## PACKAGE SERVERS
echo "${GREEN}Allow tcp connection to packages servers${RED}"
${IPT} -N PACKAGE_SERVER
for IP in ${PACKAGE_SERVER}; do
 echo "${GREEN}  - Allow tcp connection to '${IP}' on port 21,80,443${RED}"
 ${IPT} -t filter -A PACKAGE_SERVER -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} -j ACCEPT
 ${IPT} -t filter -A PACKAGE_SERVER -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} -j ACCEPT
done
${IPT} -t filter -I INPUT  2 -i ${PUB_IF} -p tcp -j PACKAGE_SERVER
${IPT} -t filter -I OUTPUT 2 -o ${PUB_IF} -p tcp -j PACKAGE_SERVER

echo "${GREEN}Allow tcp connection to useful websites on port 21,80,443${RED}"
${IPT} -N SPECIFIC_WEBSITE
for IP in ${WEBSITE}; do
 echo "${GREEN}  - Allow tcp connection to '${IP}' on port 80,443${RED}"
sudo ${IPT} -t filter -A SPECIFIC_WEBSITE -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} -j ACCEPT
sudo ${IPT} -t filter -A SPECIFIC_WEBSITE -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
done
${IPT} -t filter -I INPUT  3 -i ${PUB_IF} -p tcp -j SPECIFIC_WEBSITE
${IPT} -t filter -I OUTPUT 3 -o ${PUB_IF} -p tcp -j SPECIFIC_WEBSITE

## NTP, sync

echo "${GREEN}Allow outgoing connections to port 123 (ntp syncs)${RED}"
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p udp -s ${SERVER_IP} --dport 123 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p udp -d ${SERVER_IP} --sport 123 -m conntrack --ctstate ESTABLISHED     -j ACCEPT


###################################
## SECURITY RULES [DO NOT TOUCH] ##
###################################
echo "${GREEN}Prevent Smurfs Packets Attack${RED}"
## The attacker in this attack sends a large number of ICMP echo broadcast packet, with source IP address spoofed to that of target's IP address. All the machines in the network recieve this broadcast message and reply to the target with echo reply packet. One way to block this attack is to block all the ICMP packets, but if that can't be done, a limit may be applied to the icmp packets allowed.
${IPT} -t filter -N ICMP_RULES
echo "${GREEN}  - Drop address-mask-request and timestamp-request ping${RED}"
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type address-mask-request -j DROP
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type timestamp-request    -j DROP
echo "${GREEN}  - Allow destination-unreachable, source-quench, time-exceeded and parameter-problem ping ${RED}"
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type destination-unreachable -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j ACCEPT
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type source-quench           -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j ACCEPT
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type time-exceeded           -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j ACCEPT
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type parameter-problem       -m state --state NEW -m limit --limit 1/s --limit-burst 1 -j ACCEPT
echo "${GREEN}  - Allow limited incoming ping${RED}"
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type echo-request            -m state --state NEW -m limit --limit 10/s --limit-burst 1 -j ACCEPT
${IPT} -t filter -A ICMP_RULES -o ${PUB_IF} -p icmp -s ${SERVER_IP} -m icmp --icmp-type echo-reply -j ACCEPT
echo "${GREEN}  - Allow unlimited outgoming ping${RED}"
${IPT} -t filter -A ICMP_RULES -o ${PUB_IF} -p icmp -s ${SERVER_IP} -m icmp --icmp-type echo-request -j ACCEPT
${IPT} -t filter -A ICMP_RULES -i ${PUB_IF} -p icmp -d ${SERVER_IP} -m icmp --icmp-type echo-reply   -j ACCEPT
${IPT} -t filter -I INPUT  4 -j ICMP_RULES
${IPT} -t filter -I OUTPUT 4 -j ICMP_RULES


echo "${GREEN}Log and Drop Spoof ip       ${RED}"
${IPT} -t filter -N SPOOF_IP
for IP in ${SPOOF_IP}; do
 ${IPT} -t filter -A SPOOF_IP -i ${PUB_IF} -s ${IP} -j LOG -m limit --limit 12/min --log-level 4 --log-prefix 'SPOOFED_IP '
 ${IPT} -t filter -A SPOOF_IP -i ${PUB_IF} -s ${IP} -j DROP
done
${IPT} -t filter -I INPUT   -i ${PUB_IF} -p tcp -d ${SERVER_IP} -j SPOOF_IP
${IPT} -t filter -I OUTPUT  -o ${PUB_IF} -p tcp -s ${SERVER_IP} -j SPOOF_IP


echo "${GREEN}Log and Drop/Reject Bad tcp packets${RED}"
${IPT} -t filter -N BAD_TCP
echo "${GREEN}  - Force FRAGMENTS Packets check${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp -f -j DROP

echo "${GREEN}  - Drop INVALID packets${RED}"
${IPT} -t filter -A BAD_TCP   -m state --state INVALID -j DROP
${IPT} -t filter -A BAD_TCP -m state --state INVALID -j DROP
${IPT} -t filter -A BAD_TCP  -m state --state INVALID -j DROP

echo "${GREEN}  - Log and Drop incoming tcp packets with 0 as sport or dport${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --dport 0 -m limit --limit 6/h --limit-burst 1 -j LOG --log-prefix 'Port_0_OS_fingerprint '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --dport 0 -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p udp --dport 0 -m limit --limit 6/h --limit-burst 1 -j LOG --log-prefix 'Port 0 OS fingerprint '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p udp --dport 0 -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --sport 0 -m limit --limit 6/h --limit-burst 5 -j LOG --log-prefix 'tcp_source_port_0 '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --sport 0 -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p udp --sport 0 -m limit --limit 6/h --limit-burst 5 -j LOG --log-prefix 'udp_source_port_0 '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p udp --sport 0 -j DROP

echo "${GREEN}  - Reject New tcp packets with SYN/ACK flag${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset

echo "${GREEN}  - Log and Drop XMAS Packets${RED}"
## A christmas tree packet is a packet in which all the flags in any protocol are set. The FIN, URG and PSH bits in the -p tcp header of this kind of packet are set. This packet is called Christmas Tree packet, because all the fields of header are "lightened up" like a Christmas tree. This type of packet requires much processing than the usual packets, so the server allocates a large number of resources for this packet.
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL FIN,PSH,URG         -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix 'STEALTH_XMAS_IP '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL FIN,PSH,URG         -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix 'STEALTH_XMAS_IP '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL ALL                 -m limit --limit 5/m --limit-burst 7 -j LOG --log-prefix 'STEALTH_XMAS_IP '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL ALL                 -j DROP

echo "${GREEN}  - Log and Drop NULL Packets${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL NONE                -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix 'STEALTH_NULL_IP '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL NONE                -j DROP

echo "${GREEN}  - Log and Drop FIN Scan${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL FIN                 -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix 'STEALTH_FIN_SCAN '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags ALL FIN                 -j DROP

echo "${GREEN}  - Log and Drop SYN/RST Scan${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN,RST         -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix 'STEALTH_SYN-RST_SCAN '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,RST SYN,RST         -j DROP

echo "${GREEN}  - Log and Drop SYN/FIN Scan${RED}"
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN         -m limit --limit 3/m --limit-burst 5 -j LOG --log-prefix 'STEALTH_SYN-FIN_SCAN '
${IPT} -t filter -A BAD_TCP -i ${PUB_IF} -p tcp --tcp-flags SYN,FIN SYN,FIN          -j DROP
${IPT} -t filter -I INPUT  2 -i ${PUB_IF} -p tcp -j BAD_TCP
${IPT} -t filter -I OUTPUT 2 -o ${PUB_IF} -p tcp -j BAD_TCP


echo "${GREEN}Drop countries that shouldn't access the server${RED}"
${IPT} -N GEOIP
for IP in ${BLOCKED_COUNTRIES}; do
${IPT} -t filter -A GEOIP -m geoip --src-cc ${IP} -j DROP
done
${IPT} -t filter -I INPUT 6 -i ${PUB_IF} -p tcp -j GEOIP


echo "${GREEN}Prevent SYN Flood Attack    ${RED}"
${IPT} -t filter -I INPUT 7 -i ${PUB_IF} -p tcp  -d ${SERVER_IP} -m state --state NEW -m tcp --syn -m recent --name synflood --set
${IPT} -t filter -I INPUT 8 -i ${PUB_IF} -p tcp  -d ${SERVER_IP} -m state --state NEW -m tcp --syn -m recent --name synflood --update --seconds 1 --hitcount 10 -j DROP





################################################
## GLOBAL IPTABLES RULES. PUT HERE YOUR RULES ##
################################################

echo "${GREEN}Log and Allow SSH on port ${SSH_PORT}${RED}"
if [ -z ${PUB_SSH_ONLY} ]; then
echo "${GREEN}  - Log and Allow incoming SSH on port ${SSH_PORT}${RED}"
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -j DROP
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate NEW -j ACCEPT
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} --sport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j ACCEPT
else for IP in ${PUB_SSH_ONLY}; do
echo "${GREEN}  - Log and Allow incoming SSH on port ${SSH_PORT} from '${IP}'${RED}"
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} --dport ${SSH_PORT} -j DROP
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -s ${IP} -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate NEW -j ACCEPT
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} -d ${IP} --sport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j ACCEPT
done; fi
echo "${GREEN}  - Log and Allow outgoing SSH on port ${SSH_PORT}${RED}"
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} --sport ${SSH_PORT} -m conntrack --ctstate NEW -j LOG --log-prefix 'SSH_OUT '
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} --sport ${SSH_PORT} -m conntrack --ctstate NEW -j ACCEPT
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j LOG --log-prefix 'SSH_OUT '
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} --dport ${SSH_PORT} -m conntrack --ctstate ESTABLISHED -j ACCEPT


echo "${GREEN}Allow outgoing smtp connections${RED}"
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -s ${SERVER_IP} -m multiport --dports 25,587 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} -m multiport --sports 25,587 -m conntrack --ctstate ESTABLISHED     -j ACCEPT

# while [ "${WEB}" != "y" -a "${WEB}" != "Y" -a "${WEB}" != "n" -a "${WEB}" != "N" ]; do read -p "${YELLOW}Do you want to access a web server  - incoming tcp to port 80,443 (y/N)?${NORMAL} " WEB; done
# if [ "${WEB}" == "y" -o "${WEB}" == "Y" ]; then

# echo "${GREEN}Allow new and established incoming connections to web ports (80, 443)${RED}"
# ${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} -m multiport --dports 80,443 -m conntrack --ctstate NEW -m recent --set --name WEB
# ${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -d ${SERVER_IP} -m multiport --dports 80,443 -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount 20 --rttl --name WEB -j DROP
# ${IPT} -t filter -A INPUT  -i ${PUB_IF} -p tcp -m multiport --dports 80,443 -m limit --limit 50/s --limit-burst 50 -j ACCEPT
# ${IPT} -t filter -A OUTPUT -o ${PUB_IF} -p tcp -d ${SERVER_IP} -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
# fi


##################################
## LOG AND DROP EVERYTHING ELSE ##
##################################

echo "${GREEN}Log and Drop everything else${RED}"
${IPT} -t filter -A INPUT  -i ${PUB_IF} -j LOG -m limit --limit 5/min --log-level 4 --log-prefix 'IP_INPUT _DROP '
${IPT} -t filter -A INPUT  -i ${PUB_IF} -j DROP
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -j LOG -m limit --limit 5/min --log-level 4 --log-prefix 'IP_OUTPUT_DROP '
${IPT} -t filter -A OUTPUT -o ${PUB_IF} -j DROP





################################################
## SAVE RULES TO PREVENT FLUSHING FROM REBOOT ##
################################################

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
