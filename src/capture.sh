#!/bin/bash

# Requires root!

# Description:
#   Use airodump-ng to capture beacon frames to produce a .cap file
#   The .cap file is then used in the train.py script to
#   extract the attributes of the legitimate access point

# Usage:
#   capture.sh <interface> <essid>

airmon-ng start $1
airodump-ng $1 --write $2 --essid $2 --beacons -a --output-format pcap --write-interval 1
