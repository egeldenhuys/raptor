interface = "wlp5s0mon"
capture = True
channel = 1
captured_packet = None
sniffer = None

packs = []


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
        packs.append(packet)
        capture = False
        print("Captured a packet into 'captured_packet'. Call sniffer.stop() now")



sniffer = AsyncSniffer(iface=interface, prn=handle_packet, store=False)
hop_channel()
sniffer.start()
# sniffer.stop()
