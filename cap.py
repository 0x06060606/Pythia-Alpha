import json
import hashlib
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *

try:
    with open("data_tcp.json") as f_in_tcp:
        tcp_dat = json.load(f_in_tcp)
except FileNotFoundError:
    tcp_dat = []
try:
    with open("data_udp.json") as f_in_udp:
        udp_dat = json.load(f_in_udp)
except FileNotFoundError:
    udp_dat = []

# Normal - Normal Network Activity
# Remote - Remote Connection Activity
Status = "Normal"


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if packet[TCP].haslayer(Raw):
                payload = bytes(packet[TCP][Raw].load)
            else:
                payload = bytes(packet[TCP].payload)
            if str(src_port) == "443" or str(dst_port) == "443":
                tx_type = 'HTTPS'
            elif str(src_port) == "5900" or str(dst_port) == "5900":
                tx_type = 'VNC'
            elif str(src_port) == "22" or str(dst_port) == "22":
                tx_type = 'SSH'
            else:
                tx_type = 'UNKNOWN'
            if payload:
                packet_info = {
                    "Source IP": ip_src,
                    "Destination IP": ip_dst,
                    "Protocol": protocol,
                    "Type": tx_type,
                    "Source Port": str(src_port),
                    "Destination Port": str(dst_port),
                    "Payload": str(payload),
                    "Hash": hashlib.md5(payload).hexdigest(),
                }
                json_output = json.dumps(packet_info)
                tcp_dat.append({"label": Status, "data": json_output})
                print(json_output)
                with open("data_tcp.json", "w") as f:
                    json.dump(tcp_dat, f)
            else:
                #print("No TCP payload found in packet.")
                pass
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if packet[UDP].haslayer(Raw):
                payload = bytes(packet[UDP][Raw].load)
            else:
                payload = bytes(packet[UDP].payload)
            if payload:
                packet_info = {
                    "Source IP": ip_src,
                    "Destination IP": ip_dst,
                    "Protocol": protocol,
                    "Type": "UNKNOWN",
                    "Source Port": str(src_port),
                    "Destination Port": str(dst_port),
                    "Payload": str(payload),
                    "Hash": hashlib.md5(payload).hexdigest(),
                }
                json_output = json.dumps(packet_info)
                udp_dat.append({"label": Status, "data": json_output})
                print(json_output)
                with open("data_udp.json", "w") as f:
                    json.dump(udp_dat, f)
            else:
                #print("No UDP payload found in packet.")
                pass
        else:
            print("Unknown protocol found in packet.")
    else:
        print("No IP layer found in packet.")


sniff(prn=packet_callback, filter="ip and (tcp or udp)", store=0)
