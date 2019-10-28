#!/bin/python3

# Requires root!

# Description:
#   Capture beacon frames and monitor for inconsistencies compared to
#   the trained data.

# Usage:
#   monitor.py <interface> <json> <ssid>

import curses
import subprocess
import threading 
import sys
import json
import hashlib

from scapy.all import Dot11, sniff

interface = sys.argv[1]

# TODO: Error handling
training_file = sys.argv[2]

training_dict = {}
with open(training_file) as json_file:
    training_dict = json.load(json_file)

target_ssid = sys.argv[3]
target_ssid_bytes = bytes(target_ssid, 'utf-8')

screen = curses.initscr()
ap_list = {}
channel = 1
pad = curses.newpad(100, 200)


def hop_channel():
    global channel

    if channel == 14:
        channel = 1
    else:
        channel += 1

    subprocess.run(["iwconfig", interface, "channel", str(channel)])
    threading.Timer(0.2, hop_channel).start()


def print_aps():
    screen.clear()
    max_y, max_x = screen.getmaxyx()
    x = 0
    y = 0

    pad.addstr(y, x, 'Channel: {0} '.format(channel))
    y += 1

    pad.addstr(y, x, 'BSSID\t\t\tPWR\tCOUNT\tFREQ\tSSID\t\tHash\t\t\t\t\tROGUE')
    y += 1
    for key in ap_list:
        ap = ap_list[key]
        pad.addstr(y, x, '{0}\t{1}\t{2}\t{3}\t{5}\t{6}\t{7}'.format(str(ap['bssid']), str(ap['dBm_AntSignal']), str(ap['beacon_count']), str(ap['channel']), str(ap['bfs']), str(ap['ssid']), ap['hash'], ap['rogue']))
        y = y + 1

    pad.refresh(0, 0, 0, 0, max_y-1, max_x-1)


def hash_packet(packet):
    # Layer 5 should have the ID 5 (TIM)
    if packet[5].ID != 5:
        print('ERROR')
        packet.display()
        exit(1)

    # Ignore timestamp and SC
    ts = packet.timestamp
    packet.timestamp = 0
    packet.SC = 0

    # Ignore TIM
    packet[5].len = 1
    # Not sure why both need to be set. Some scapy magic
    packet[5].info = b'\x00'
    packet[5].fields["info"] = b'\x00'

    # Remove HTInfo since it can change over time
    for i in range(0, len(packet.layers())):
        if "ID" in packet[i].fields:
            if packet[i].ID == 61:
                if "info" not in packet[i].fields:
                    print('Packet does not contain INFO')

                packet[i].len = 1
                packet[i].info = b'\x00'
                packet[i].fields["info"] = b'\x00'

    result = hashlib.md5(raw(packet))
    packet_hash = result.hexdigest()

    return packet_hash


def PacketHandler(packet):
    if packet.type == 0 and packet.subtype == 8:
        if packet.info == target_ssid_bytes:
            # Check 1: MAC Address

            if packet.addr2 == 'e8:99:c4:7c:6c:11' or packet.addr2 == 'f8:c3:9e:b9:95:41':
                packet.addr2 = '00:ad:24:f9:34:79'
                packet.addr3 = '00:ad:24:f9:34:79'
            elif packet.addr2.startswith('02:08:22'):
                packet.addr2 = '00:0f:00:75:51:08'
                packet.addr3 = '00:0f:00:75:51:08'

            tim_len = packet[6].len

            packet_len = len(packet) - tim_len

            radiotap_dummy_len = len(packet) - len(packet[1])
            packet_len = packet_len - radiotap_dummy_len

            # Scapy adds a nice radiotap header, but it is not present
            # in the pcap, causing the hashes to differ. Strip it here
            packet_hash = hash_packet(packet[1])

            # TODO(egeldenhuys): Channel can differentiate even further
            key = packet_hash

            # ap dict is used for printing
            if key in ap_list:
                ap = ap_list[key]
                ap['beacon_count'] = ap['beacon_count'] + 1
                ap['dBm_AntSignal'] = packet.dBm_AntSignal
            else:
                # if key[0] in training_dict:
                #     bfs_string = str(packet_len) + ' | ' + str(training_dict[key[0]])
                # else:
                #     bfs_string = str(packet_len)

                ap = {
                    'bssid': str(packet.addr2),
                    'ssid': str(packet.info),
                    'beacon_count': 1,
                    'dBm_AntSignal': packet.dBm_AntSignal,
                    'bfs': packet_len,
                    'channel': packet.ChannelFrequency,
                    'hash': packet_hash,
                    'rogue': ''
                }

                mac = ap['bssid']

                if mac not in training_dict:
                    ap['rogue'] = 'YES. Unknown BSSID'
                elif ap['hash'] != training_dict[mac]['hash']:
                    ap['rogue'] = "YES. Hash != " + training_dict[mac]['hash']

                ap_list[key] = ap
            print_aps()


hop_channel()

sniff(iface=interface, prn=PacketHandler, store=0, monitor=False)
curses.endwin()
