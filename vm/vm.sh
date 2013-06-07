#!/bin/bash
#Author: Wouter Miltenburg
#This script is for installing a RADIUS chain of servers that will automatically install the
#freeradius mod from: https://github.com/MoonshotNL/moonshotcode

while true
do
echo "Please read the README before using this script."
echo "Is this the server one of the following choice"
echo "Root RADIUS (root)"
echo "LDAP server (ldap)"
echo "Home insitution RADIUS (home)"
echo "Please select your choice (root/ldap/home/exit)"
read a

case "$a" in
	"root")
			echo "Installation in progress"
			yum -y update
			yum -y install make autoconf gcc wget openssl-devel
			
			cd /usr/src
			wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.1.12.tar.gz
			tar -xzf freeradius-server-2.1.12.tar.gz
			rm -f freeradius-server-2.1.12.tar.gz
			sleep 0.5
			
			cd ./freeradius-server-2.1.12.tar.gz
			./configure
			make
			make install
			
			cd ./modules
			git clone git://github.com/MoonshotNL/moonshotcode.git
			mkdir rlm_moonshot
			cp -vR ./moonshotcode/freeradius_smime/modules/* ./
			rm -vrf ./moonshotcode
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