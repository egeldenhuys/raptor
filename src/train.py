#!/bin/python3

# Description:
#   Process pcap file to extract attributes of legitimate access points.
#   Produces a JSON file that is used for monitoring named <ssid>.json

# Usage:
#   train.py <capture_file> <ssid>

import sys
import json
import hashlib

from scapy.all import *


def filter_pcap(pcap, target_ssid):
    filtered = []

    target_ssid_bytes = bytes(target_ssid, 'utf-8')

    for packet in pcap:
        if packet.type == 0 and packet.subtype == 8:
            if packet.info == target_ssid_bytes:
                filtered.append(packet)

    return filtered


def get_aps(filtered_pcap):
    # NOTE: TIM len is not included!
    # TODO(egeldenhuys): Rename to more accurate description. This calculates BFS
    macs = {}

    for packet in filtered_pcap:
        # Layer 5 should have the ID 5 (TIM)
        if packet[5].ID != 5:
            print('ERROR')
            packet.show()
            exit(1)

        tim_len = packet[5].len
        packet_len = len(packet) - tim_len

        if str(packet.addr2) not in macs:
            macs[str(packet.addr2)] = packet_len
        else:
            if macs[str(packet.addr2)] != packet_len:
                print('ERROR! Varying BFS even when TIM is ignored')
                print('Did you capture a rogue AP in the training data?')
                packet.show()

    return macs


def hash_packets(filtered_pcap):
    hashes = {}

    index = 0
    for packet in filtered_pcap:
        # Layer 5 should have the ID 5 (TIM)
        if packet[5].ID != 5:
            print('ERROR')
            packet.show()
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
                        print('Packet index ' + str(index) + ' does not contain INFO')

                    packet[i].len = 1
                    packet[i].info = b'\x00'
                    packet[i].fields["info"] = b'\x00'

        result = hashlib.md5(raw(packet))
        packet_hash = result.hexdigest()

        # TODO(egeldenhuys): Alert if hash does not match existing hash. Could be rogue
        if str(packet.addr2) not in hashes:
            hashes[str(packet.addr2)] = packet_hash
            print('0 - ' + str(packet.addr2) + ' - ' + str(index) + ' ts:' + str(ts))
        else:
            if packet_hash not in hashes[str(packet.addr2)]:
                hashes[str(packet.addr2)] = packet_hash
                print('1 - ' + str(packet.addr2) + ' - ' + str(index) + ' ts:' + str(ts))
        index += 1

    return hashes


def combine_bfs_hashes(bfs, hashes):
    combined = {}

    for mac in bfs.keys():
        if mac not in combined:
            combined[mac] = {}
            combined[mac]["bfs"] = bfs[mac]

    for mac in hashes.keys():
        if mac in combined:
            combined[mac]["hash"] = hashes[mac]

    return combined

# TODO(egeldenhuys): Handle incorrect args


pcap_file = sys.argv[1]
target_ssid = sys.argv[2]

print('Reading ' + pcap_file + '...')
# TODO(egeldenhuys): Use faster method of reading pcap
# https://github.com/secdev/scapy/issues/253
pcap = rdpcap(pcap_file)

print('Filtering...')
filtered = filter_pcap(pcap, target_ssid)
print('{0} beacon frames found'.format(str(len(filtered))))

# print('Writing filtered packet capture to ' + output_file)
# wrpcap(output_file, filtered)

print('Extracting APs...')
macs = get_aps(filtered)
print('{0} APs found'.format(len(macs)))

# macs_json = json.dumps(macs)
# f = open(output_file,'w')
# f.write(macs_json)
# f.close()

print("Hashing packets...")
hashes = hash_packets(filtered)
# print("Writing hashes...")
# hashes_json = json.dumps(hashes)
# f = open(target_ssid + ".json", 'w')
# f.write(hashes_json)
# f.close()
# print("Done")

print("Writing to " + target_ssid + ".json")
combined = combine_bfs_hashes(macs, hashes)
combined_json = json.dumps(combined)
f = open(target_ssid + ".json", 'w')
f.write(combined_json)
f.close()
