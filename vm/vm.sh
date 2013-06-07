#!/bin/bash
#Author: Wouter Miltenburg
#This script is for installing a RADIUS chain of servers that will automatically install the
#freeradius mod from: https://github.com/MoonshotNL/moonshotcode

while true
do
echo "Please read the README before using this script."
echo "Is this the server one of the following choice"
echo "Root RADIUS (root)" #IP address:192.168.56.11
echo "LDAP server (ldap)" #IP address:192.168.56.13
echo "Home insitution RADIUS (home)" #IP address:192.168.56.12
#Janet IP address:192..168.56.14
echo "Please select your choice (root/ldap/home/exit)"
read a

case "$a" in
	"root")
			echo "Installation in progress"
			yum -y update
			yum -y install make autoconf gcc wget openssl-devel git
			
			cd /etc/sysconfig/network-scripts
			cat ifcfg-eth1 > ifcfg-eth1_old
			sed "s/^ONBOOT=.*/ONBOOT=yes/g" -e "s/^BOOTPROTO=.*/BOOTPROTO=static/g" ifcfg-eth1 > ifcfg-eth1_new
			echo "
IPADDR=192.168.56.11
NETMASK=255.255.255.0" >> ifcfg-eth1_new
			mv ifcfg-eth1_new ifcfg-eth1
			
			cd /usr/src
			wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.1.12.tar.gz
			tar -xzf freeradius-server-2.1.12.tar.gz
			rm -f freeradius-server-2.1.12.tar.gz
			sleep 0.5
			
			cd ./freeradius-server-2.1.12
			./configure
			make
			make install
			
			cd ./modules
			git clone git://github.com/MoonshotNL/moonshotcode.git
			mkdir rlm_moonshot
			cp -vR ./moonshotcode/freeradius_smime/modules/* ./
			cd ./modules
			sleep 0.5
			#make
			#make install
			cd ..
			rm -rvf ./moonshotcode
			
			cd /usr/local/etc/raddb
			echo "
realm moonshot.nl{
	type = radius
	authhost = 192.168.56.12:1812
	accthost = 192.168.56.12:1813
	secret = testing123
}" >> proxy.conf

		echo "
client localradtest{
	ipaddr = 192.168.56.11
	secret = testing123
	require_message_authenticator = no
	nastype = other
}

client janet{
	ipaddr = 192.168.56.14
	secret = testing123
	require_message_authenticator = no
	nastype = other
}" >> clients.conf
			
			cat eap.conf > eap.conf_old
			sed "s/default_eap_type = md5/default_eap_type = ttls/g" eap.conf_old > eap_conf_new
			mv eap_conf_new eap.conf
			
			break
			;;
			
	"home")
			echo "Installation in progress"
			yum -y update
			yum -y install make autoconf gcc wget openssl-devel git

			cd /etc/sysconfig/network-scripts
			cat ifcfg-eth1 > ifcfg-eth1_old
			sed "s/^ONBOOT=.*/ONBOOT=yes/g" -e "s/^BOOTPROTO=.*/BOOTPROTO=static/g" ifcfg-eth1 > ifcfg-eth1_new
			echo "
IPADDR=192.168.56.12
NETMASK=255.255.255.0" >> ifcfg-eth1_new
			mv ifcfg-eth1_new ifcfg-eth1

			cd /usr/src
			wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.1.12.tar.gz
			tar -xzf freeradius-server-2.1.12.tar.gz
			rm -f freeradius-server-2.1.12.tar.gz
			sleep 0.5

			cd ./freeradius-server-2.1.12
			./configure
			make
			make install

			cd ./modules
			git clone git://github.com/MoonshotNL/moonshotcode.git
			mkdir rlm_moonshot
			cp -vR ./moonshotcode/freeradius_smime/modules/* ./
			cd ./modules
			sleep 0.5
			#make
			#make install
			cd ..
			rm -rvf ./moonshotcode

			cd /usr/local/etc/raddb

			echo "
client localradtest{
	ipaddr = 192.168.56.12
	secret = testing123
	require_message_authenticator = no
	nastype = other
}

client janet{
	ipaddr = 192.168.56.14
	secret = testing123
	require_message_authenticator = no
	nastype = other
}

client root_radius{
	ipaddr = 192.168.56.11
	secret = testing123
	require_message_authenticator = no
	nastype = other
}" >> clients.conf

			cat eap.conf > eap.conf_old
			sed "s/default_eap_type = md5/default_eap_type = ttls/g" eap.conf_old > eap_conf_new
			mv eap_conf_new eap.conf
			
			cd ./sites-enabled
			
			wget https://raw.github.com/MoonshotNL/moonshotcode/master/vm/configuration_files/inner-tunnel_conf
			cat inner-tunnel_conf > ../sites-available/inner-tunnel
			wget https://raw.github.com/MoonshotNL/moonshotcode/master/vm/configuration_files/default_conf
			cat default_conf > ../sites-available/default
			
			cd ..
			wget https://raw.github.com/MoonshotNL/moonshotcode/master/vm/configuration_files/ldap_conf
			mv ldap_conf ./modules/ldap
			
			
			
			echo "
checkitem	Cleartext-Password		userPassword" >> ldap.attrmap
			
			break
			;;
			
	"exit")
			echo "Installation aborted by user."
			break
			;;
	
	*)
			echo "Invalid input."
			;;
			
esac

done