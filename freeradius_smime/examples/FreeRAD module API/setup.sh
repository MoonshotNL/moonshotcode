#CentOS 6.4 64-bit clean install expected

yum -y update

yum -y install make
yum -y install gcc
yum -y install wget
yum -y install openssl-devel

cd /usr/src
wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.1.12.tar.gz
tar -xzf freeradius-server-2.1.12.tar.gz
rm -f freeradius-server-2.1.12.tar.gz
cd freeradius-server-2.1.12

./configure
make
make install
cd src
make
make install
cd modules

cp -R ./rlm_example ./rlm_testing
cd ./rlm_testing
mv rlm_example.c rlm_testing.c
cat configure.in | awk '{gsub("example", "testing"); print}' > configure.in.tmp
mv -f configure.in.tmp configure.in
./configure