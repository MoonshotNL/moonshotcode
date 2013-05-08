#CentOS 6.4 64-bit clean install expected

yum -y update

yum -y install make
yum -y install autoconf
yum -y install gcc
yum -y install wget
yum -y install openssl-devel

cd /usr/src
wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-2.1.12.tar.gz
tar -xzf freeradius-server-2.1.12.tar.gz
rm -f freeradius-server-2.1.12.tar.gz
sleep 0.5
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
sleep 0.5
cat Makefile.in | awk '{gsub("example", "testing"); print}' > Makefile.in.tmp
sleep 0.5
cat Makefile.clean | awk '{gsub("example", "testing"); print}' > Makefile.clean.tmp
sleep 0.5
cat rlm_testing.c | awk '{gsub("example", "testing"); print}' > rlm_testing.c.tmp
sleep 0.5

mv -f configure.in.tmp configure.in
mv -f Makefile.in.tmp Makefile.in
mv -f Makefile.clean.tmp Makefile.clean
mv -f rlm_testing.c.tmp rlm_testing.c
sleep 1

autoconf
./configure