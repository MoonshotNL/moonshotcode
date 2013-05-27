#!/bin/bash

yum -yq install zlib-devel.x86_64
yum -yq install openssl-devel.x86_64
yum -yq install pam-devel.x86_64
yum -yq install wget
yum -yq install make
yum -yq install gcc
yum -yq install gdb

wget http://www.mindrot.org/openssh_snap/openssh-SNAP-20130322.tar.gz
tar -xzf openssh-SNAP-20130322.tar.gz
cd openssh

./configure --with-pam --sysconfdir=/etc/ssh

sed -i -e 's/CFLAGS=-g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -fno-builtin-memset -fstack-protector-all/CFLAGS=-ggdb -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -fno-builtin-memset -fstack-protector-all/' Makefile
sed -i -e 's/CFLAGS=-g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -fno-builtin-memset -fstack-protector-all/CFLAGS=-ggdb -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wformat-security -Wno-pointer-sign -fno-strict-aliasing -D_FORTIFY_SOURCE=2 -fno-builtin-memset -fstack-protector-all/' openbsd-compat/Makefile

make
