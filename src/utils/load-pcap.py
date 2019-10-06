pcap_file = "lolwat.cap"
target_ssid = "lolwat"

pcap = rdpcap(pcap_file)

def filter_pcap(pcap, target_ssid):
    filtered = []

    target_ssid_bytes = bytes(target_ssid, 'utf-8')

    for packet in pcap:
        if packet.type == 0 and packet.subtype == 8:
            if packet.info == target_ssid_bytes:
                filtered.append(packet)

    return filtered

filtered = filter_pcap(pcap, target_ssid)
