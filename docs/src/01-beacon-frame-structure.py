# Dump the first captured beacon frame to PDF

# Usage:
#   sudo airmon-ng start <interface>
#   01-beacon-frame-structure.py <monitor_interface>

import subprocess
import threading 
import sys

from scapy.all import AsyncSniffer

interface = sys.argv[1]

capture = True
channel = 1
captured_packet = None
sniffer = None


def hop_channel():
    global channel

    if channel == 14:
        channel = 1
    else:
        channel += 1

    subprocess.run(["iwconfig", interface, "channel", str(channel)])
    if capture:
        threading.Timer(0.2, hop_channel).start()


def handle_packet(packet):
    global captured_packet
    global capture
    global sniffer
    if packet.type == 0 and packet.subtype == 8:
        captured_packet = packet
        capture = False
        sniffer.stop()


print("Starting capture...")
sniffer = AsyncSniffer(iface=interface, prn=handle_packet, store=False)
hop_channel()
sniffer.start()
sniffer.join()

print("Generating PDF...")
captured_packet.pdfdump("01-beacon-frame.pdf", layer_shift=1)
