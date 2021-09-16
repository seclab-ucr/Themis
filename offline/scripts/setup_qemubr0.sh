#!/bin/bash

sudo ip link add name qemubr0 type bridge
sudo ip addr add 192.168.100.1/24 dev qemubr0
sudo ip link set qemubr0 up

