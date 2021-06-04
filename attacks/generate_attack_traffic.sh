#!/bin/bash

sudo rm ../pcaps/*

sudo python3 rst_rightmost_sack_server.py &

sudo python3 in_window_rst.py
sudo python3 in_window_syn.py
sudo python3 md5_data.py
sudo python3 md5_rst.py
sudo python3 no_ack_flag.py
sudo python3 rst_rightmost_sack.py
sudo python3 syn_fin.py
