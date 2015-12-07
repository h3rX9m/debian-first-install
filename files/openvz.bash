#!/bin/bash

echo "deb http://download.openvz.org/debian wheezy main" >> /etc/apt/sources.list.d/openvz.list
wget http://ftp.openvz.org/debian/archive.key
apt-key add archive.key
apt-get -qq update
apt-get install -qqy linux-image-openvz-amd64
echo '# On Hardware Node we generally need
# packet forwarding enabled and proxy arp disabled
net.ipv4.ip_forward = 1
 
# Enables source route verification
net.ipv4.conf.all.rp_filter = 1
 
# Enables the magic-sysrq key
kernel.sysrq = 1

# We do not want all our interfaces to send redirects
net.ipv4.conf.default.send_redirects = 1
net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf
apt-get install -qqy vzctl vzquota ploop vzstats

sed -i 's/GRUB_DEFAULT=0/GRUB_DEFAULT=2/' /etc/default/grub
update-grub
