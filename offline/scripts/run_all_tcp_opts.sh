#!/bin/bash

if [ ! -z $1 ]; then
    OUTPUT_DIR=$1
else
    OUTPUT_DIR=results
fi

mkdir -p $OUTPUT_DIR

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 0/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 0/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.none
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.none
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.none
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 2/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 4/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts mss > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.mss
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.mss
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.mss
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 2/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 3/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts wscale > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.wscale
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.wscale
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.wscale
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 2/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 2/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts sackok > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.sackok
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.sackok
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.sackok
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 2/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 10/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts sack > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.sack
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.sack
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.sack
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 2/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 10/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts timestamp > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.timestamp
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.timestamp
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.timestamp
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 2/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 18/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts md5 > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.md5
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.md5
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.md5
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 2/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 2/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts fastopenreq > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.fastopenreq
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.fastopenreq
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.fastopenreq
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 2/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 10/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts fastopen > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.fastopen
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.fastopen
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.fastopen
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 4/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 4/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts expfastopenreq > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.expfastopenreq
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.expfastopenreq
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.expfastopenreq
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 4/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 12/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts expfastopen > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.expfastopen
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.expfastopen
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.expfastopen
sleep 5

# modify s2e-config.lua
sed -i 's/symbolicTCPOptionsStart = [0-9]\+/symbolicTCPOptionsStart = 6/g' s2e-config.lua
sed -i 's/symbolicTCPOptionsEnd = [0-9]\+/symbolicTCPOptionsEnd = 6/g' s2e-config.lua
echo "Starting S2E..."
./launch-s2e.sh &
# wait for S2E to fully start
sleep 20
sudo scripts/packet_sender.py -p 20 --tcp-opts smc > /dev/null 2>&1 &
# wait for S2E to finish
QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
while [ $QEMU != '1' ]; do
    sleep 5
    QEMU=`ps -ef|grep qemu|grep $(whoami)|wc -l`
done 
sudo pkill -f packet_sender
# create a symbolic link for the results dir
rm $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.smc
ln -s $(realpath "s2e-last") $OUTPUT_DIR/s2e-out-3pkts.p20.fixed_doff.smc
scripts/get_concrete_examples.py > $OUTPUT_DIR/s2e.3pkts.p20.fixed_doff.smc
sleep 5


