#!/bin/bash

yum -yq install zlib-devel.x86_64
yum -yq install openssl-devel.x86_64
yum -yq install pam-devel.x86_64
yum -yq install wget
yum -yq install make
yum -yq install gcc

wget http://ftp.nluug.nl/pub/OpenBSD/OpenSSH/portable/openssh-6.1p1.tar.gz
tar -xzf openssh-6.1p1.tar.gz
cd openssh-6.1p1

yum -yq erase openssh-server

./configure --with-pam --sysconfdir=/etc/ssh
make
make install

cd ..
rm -fR openssh-6.1p1*

/usr/local/sbin/sshd

INITSCRIPT="sshd_init.sh"
echo "#!/bin/bash" > $INITSCRIPT
echo "" >> $INITSCRIPT
echo "start()" >> $INITSCRIPT
echo "{" >> $INITSCRIPT
echo "	echo \"Starting sshd...\"" >> $INITSCRIPT
echo "	/usr/local/sbin/sshd" >> $INITSCRIPT
echo "}" >> $INITSCRIPT
echo "" >> $INITSCRIPT
echo "stop()" >> $INITSCRIPT
echo "{" >> $INITSCRIPT
echo "	echo \"Stopping sshd...\"" >> $INITSCRIPT
echo "	pkill -f /usr/local/sbin/sshd" >> $INITSCRIPT
echo "}" >> $INITSCRIPT
echo "" >> $INITSCRIPT
echo "restart()" >> $INITSCRIPT
echo "{" >> $INITSCRIPT
echo "	stop" >> $INITSCRIPT
echo "	start" >> $INITSCRIPT
echo "}" >> $INITSCRIPT
echo "" >> $INITSCRIPT
echo "status()" >> $INITSCRIPT
echo "{" >> $INITSCRIPT
echo "	PIDS=\`pgrep -f /usr/local/sbin/sshd\`" >> $INITSCRIPT
echo "	if [ -n \"\$PIDS\" ]" >> $INITSCRIPT
echo "	then" >> $INITSCRIPT
echo "		echo \"sshd is running...\"" >> $INITSCRIPT
echo "	else" >> $INITSCRIPT
echo "		echo \"sshd is not running...\"" >> $INITSCRIPT
echo "	fi" >> $INITSCRIPT
echo "}" >> $INITSCRIPT
echo "" >> $INITSCRIPT
echo "case \"\$1\" in" >> $INITSCRIPT
echo "	start)" >> $INITSCRIPT
echo "		start" >> $INITSCRIPT
echo "		;;" >> $INITSCRIPT
echo "	stop)" >> $INITSCRIPT
echo "		stop" >> $INITSCRIPT
echo "		;;" >> $INITSCRIPT
echo "	restart)" >> $INITSCRIPT
echo "		restart" >> $INITSCRIPT
echo "		;;" >> $INITSCRIPT
echo "	status)" >> $INITSCRIPT
echo "		status" >> $INITSCRIPT
echo "		;;" >> $INITSCRIPT
echo "	*)" >> $INITSCRIPT
echo "		echo \"Usage: \$0 {start|stop|restart|status}\"" >> $INITSCRIPT
echo "esac" >> $INITSCRIPT

chmod +x $INITSCRIPT