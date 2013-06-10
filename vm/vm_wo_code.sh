#!/bin/bash
#Author: Wouter Miltenburg / Koen Veelenturf
#This script is for installing a RADIUS chain of servers that will automatically install the
#freeradius mod from: https://github.com/MoonshotNL/moonshotcode

while true
do
echo "===================================================="
echo "WARNING:"
echo "Do not use this script in a live environment"
echo "===================================================="
echo "Please read the README before using this script."
echo "Is this the server one of the following choice"
echo "Root RADIUS (root)" #IP address:192.168.56.11 -> 10.198.128.10
echo "LDAP server (ldap)" #IP address:192.168.56.13 -> 10.198.128.11
echo "Home insitution RADIUS (home)" #IP address:192.168.56.12 -> 10.198.128.12
#Janet IP address:192.168.56.14
echo "Please select your choice (root/ldap/home/exit)"
read a

case "$a" in
	"root")
			echo "Installation in progress"
			yum -y update
			yum -y install make autoconf gcc wget openssl-devel git openldap-devel man
			
#			cd /etc/sysconfig/network-scripts
#			cat ifcfg-eth1 > ifcfg-eth1_old
#			sed "s/^ONBOOT=.*/ONBOOT=yes/g" -e "s/^BOOTPROTO=.*/BOOTPROTO=static/g" ifcfg-eth1 > ifcfg-eth1_new
#			echo "
#IPADDR=192.168.56.11
#NETMASK=255.255.255.0" >> ifcfg-eth1_new
#			mv ifcfg-eth1_new ifcfg-eth1
			
			cd /usr/src
			wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.1.12.tar.gz
			tar -xzf freeradius-server-2.1.12.tar.gz
			rm -f freeradius-server-2.1.12.tar.gz
			sleep 0.5
			
			cd ./freeradius-server-2.1.12
			./configure
			make
			make install
			
			cd ./src/modules
			wget https://dl.dropboxusercontent.com/u/11255615/moonshot.tar.gz
			tar -xzvf moonshot.tar.gz	
			sleep 0.5
			mkdir rlm_moonshot
			cp -vR ./moonshotcode-master/freeradius_smime/modules/* ./rlm_moonshot
			#cd ./rlm_moonshot
			#sleep 0.5
			#./configure
			#make
			#make install
			#sleep 1.0
			#cd ..
			rm -rvf ./moonshotcode-master
			
			cd /usr/local/etc/raddb
			echo "
realm moonshot.nl{
	type = radius
	authhost = 10.198.128.12:1812
	accthost = 10.198.128.12:1813
	secret = testing123
}" >> proxy.conf

		echo "
client localradtest{
	ipaddr = 10.198.128.10
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
			rm -f eap.conf_old
			
			break
			;;
			
	"home")
			echo "Installation in progress"
			yum -y update
			yum -y install make autoconf gcc wget openssl-devel git openldap-devel man

#			cd /etc/sysconfig/network-scripts
#			cat ifcfg-eth1 > ifcfg-eth1_old
#			sed "s/^ONBOOT=.*/ONBOOT=yes/g" -e "s/^BOOTPROTO=.*/BOOTPROTO=static/g" ifcfg-eth1 > ifcfg-eth1_new
#			echo "
#IPADDR=192.168.56.12
#NETMASK=255.255.255.0" >> ifcfg-eth1_new
#			mv ifcfg-eth1_new ifcfg-eth1

			cd /usr/src
			wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.1.12.tar.gz
			tar -xzf freeradius-server-2.1.12.tar.gz
			rm -f freeradius-server-2.1.12.tar.gz
			sleep 0.5

			cd ./freeradius-server-2.1.12
			./configure
			make
			make install

			cd ./src/modules
                        wget https://dl.dropboxusercontent.com/u/11255615/moonshot.tar.gz
                        tar -xzvf moonshot.tar.gz
			sleep 0.5
			mkdir rlm_moonshot
			cp -vR ./moonshotcode-master/freeradius_smime/modules/* ./rlm_moonshot
			#cd ./rlm_moonshot
			#sleep 0.5
			#./configure
			#make
			#make install
			#sleep 0.5
			#cd ..
			rm -rvf ./moonshotcode-master

			cd /usr/local/etc/raddb

			echo "
client localradtest{
	ipaddr = 10.198.128.12
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
	ipaddr = 10.198.128.10
	secret = testing123
	require_message_authenticator = no
	nastype = other
}" >> clients.conf

			cat eap.conf > eap.conf_old
			sed "s/default_eap_type = md5/default_eap_type = ttls/g" eap.conf_old > eap_conf_new
			mv eap_conf_new eap.conf
			rm -f eap.conf_old
			
			cd ./sites-enabled
			
			wget https://dl.dropboxusercontent.com/u/11255615/inner-tunnel_conf
			sleep 0.5
			cat inner-tunnel_conf > ../sites-available/inner-tunnel
			rm -f inner-tunnel_conf
			sleep 0.5
			
			wget https://dl.dropboxusercontent.com/u/11255615/default_conf
			sleep 0.5
			cat default_conf > ../sites-available/default
			rm -f default_conf
			sleep 0.5
			
			cd ..
			wget https://dl.dropboxusercontent.com/u/11255615/ldap_conf
			sleep 0.5
			mv ldap_conf ./modules/ldap
			
			
			
			echo "
checkitem	Cleartext-Password		userPassword" >> ldap.attrmap
			
			break
			;;
			
	"ldap")
			yum -y update
			yum -y install make autoconf gcc wget openssl-devel git man
			yum -y install openldap-servers openldap-clients
			
#			cd /etc/sysconfig/network-scripts
#			cat ifcfg-eth1 > ifcfg-eth1_old
#			sed "s/^ONBOOT=.*/ONBOOT=yes/g" -e "s/^BOOTPROTO=.*/BOOTPROTO=static/g" ifcfg-eth1 > ifcfg-eth1_new
#			echo "
#IPADDR=192.168.56.13
#NETMASK=255.255.255.0" >> ifcfg-eth1_new
#			mv ifcfg-eth1_new ifcfg-eth1
			
			cd /etc/openldap
			wget https://raw.github.com/MoonshotNL/moonshotcode/master/vm/configuration_files/slapd_conf.conf
			mv slapd_conf.conf slapd.conf
			sleep 0.5
			
			cd /etc/openldap/schema
			wget https://raw.github.com/MoonshotNL/moonshotcode/master/vm/configuration_files/radius.schema_conf
			mv radius.schema_conf radius.schema
			cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG
			wget https://raw.github.com/MoonshotNL/moonshotcode/master/vm/configuration_files/initial_conf.ldif
			mv initial_conf.ldif initial.ldif
			
			chown -R ldap:ldap /var/lib/ldap
			rm -rf /etc/openldap/slapd.d
			
			service slapd start
			
			sleep 1.0
			
			ldapadd -h localhost -D "cn=Manager,dc=moonshot,dc=nl" -f initial.ldif -w test
			
			chkconfig slapd on
			
			
			
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
