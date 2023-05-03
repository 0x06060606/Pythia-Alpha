import json
import hashlib
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *

try: # Load data from previous runs
    with open("data_tcp.json") as f_in_tcp:
        tcp_dat = json.load(f_in_tcp) # Load data from previous runs
except FileNotFoundError:
    tcp_dat = [] # Create empty lists if no data is found
try:
    with open("data_udp.json") as f_in_udp:
        udp_dat = json.load(f_in_udp) # Load data from previous runs
except FileNotFoundError:
    udp_dat = [] # Create empty lists if no data is found

# 
# Normal - Normal Network Activity
# Remote - Remote Connection Activity
# Malicious - Malicious Network Activity
# Unknown - Unknown Network Activity
#
Status = "Normal" # Normal, Remote, Malicious, Unknown


def packet_callback(packet): # Packet callback function
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
                packet_info = { # Packet information
                    "Source IP": ip_src, # Source IP
                    "Destination IP": ip_dst, # Destination IP
                    "Protocol": protocol, # Protocol
                    "Type": tx_type, # Type
                    "Source Port": str(src_port), # Source Port
                    "Destination Port": str(dst_port), # Destination Port
                    "Payload": str(payload), # Payload
                    "Hash": hashlib.md5(payload).hexdigest(), # Hash
                } 
                json_output = json.dumps(packet_info)
                tcp_dat.append({"label": Status, "data": json_output})
                print(json_output) # Print packet information
                with open("data_tcp.json", "w") as f:
                    json.dump(tcp_dat, f) # Write data to file
            else:
                pass # No TCP payload found in packet.
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if packet[UDP].haslayer(Raw):
                payload = bytes(packet[UDP][Raw].load)
            else:
                payload = bytes(packet[UDP].payload)
            if payload:
                packet_info = { # Packet information
                    "Source IP": ip_src, # Source IP
                    "Destination IP": ip_dst, # Destination IP
                    "Protocol": protocol, # Protocol
                    "Type": "UNKNOWN", # Type
                    "Source Port": str(src_port), # Source Port
                    "Destination Port": str(dst_port), # Destination Port
                    "Payload": str(payload), # Payload
                    "Hash": hashlib.md5(payload).hexdigest(), # Hash
                } 
                json_output = json.dumps(packet_info)
                udp_dat.append({"label": Status, "data": json_output})
                print(json_output) # Print packet information
                with open("data_udp.json", "w") as f:
                    json.dump(udp_dat, f) # Write data to file
            else:
                pass # No UDP payload found in packet.
        else:
            pass # No TCP or UDP Layer
    else:
        pass # No IP Layer

# Sniff for TCP and UDP packets
sniff(prn=packet_callback, filter="ip and (tcp or udp)", store=0)
# End of File
