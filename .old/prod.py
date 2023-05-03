import joblib
import json
import hashlib
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *
import numpy as np
import subprocess
import struct
import ipaddress
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

defines = ["Normal Traffic", "Remote Connection Traffic"]


def is_local_ip(ip):
    return ipaddress.ip_address(ip).is_private


def block_ip(ip):
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True
        )
        print(f"Successfully blocked IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"Failed to block IP: {ip}")


def preprocess_data(df: pd.DataFrame):
    df["Source IP"] = df["Source IP"].apply(
        lambda x: int(
            str(
                int.from_bytes(
                    hashlib.sha256(x.encode("utf-8")).digest(),
                    byteorder="big",
                    signed=False,
                )
            )[:38]
        )
    )
    df["Destination IP"] = df["Destination IP"].apply(
        lambda x: int(
            str(
                int.from_bytes(
                    hashlib.sha256(x.encode("utf-8")).digest(),
                    byteorder="big",
                    signed=False,
                )
            )[:38]
        )
    )
    df["Payload_length"] = df["Payload"].apply(len)
    df["Hash"] = (
        df["Hash"]
        .astype("category")
        .apply(
            lambda x: int(
                str(
                    int.from_bytes(
                        hashlib.sha256(x.encode("utf-8")).digest(),
                        byteorder="big",
                        signed=False,
                    )
                )[:38]
            )
        )
    )
    df["Payload"] = df["Payload"].apply(
        lambda x: int(
            str(
                int.from_bytes(
                    hashlib.sha256(x.encode("utf-8")).digest(),
                    byteorder="big",
                    signed=False,
                )
            )[:38]
        )
    )
    df["Type"] = df["Type"].apply(
        lambda x: int(
            str(
                int.from_bytes(
                    hashlib.sha256(x.encode("utf-8")).digest(),
                    byteorder="big",
                    signed=False,
                )
            )[:38]
        )
    )
    print(df)
    df = pd.get_dummies(df, columns=["Protocol"])
    X = df.drop("label", axis=1)
    Y = df["label"]
    return (df, X, Y)


def predict_score(new_data, dat_type):
    model = joblib.load("model_" + dat_type + ".pkl")
    new_data = pd.DataFrame(new_data, index=[0])
    preprocessed_data = preprocess_data(new_data)
    prediction = model.predict_proba(preprocessed_data)
    # positive_class_score = prediction[0][1]
    return prediction


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
                tx_type = "HTTPS"
            elif str(src_port) == "5900" or str(dst_port) == "5900":
                tx_type = "VNC"
            elif str(src_port) == "22" or str(dst_port) == "22":
                tx_type = "SSH"
            else:
                tx_type = "UNKNOWN"
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
                # print(json_output)
                score = predict_score(packet_info, "tcp")
                print("TCP Data Score:", score)
                max_index = np.argmax(score[0])
                print(defines[max_index])
                if max_index == 1:
                    print(ip_src)
                    if is_local_ip(ip_src):
                        pass
                    else:
                        block_ip(ip_src)
            else:
                # print("No TCP payload found in packet.")
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
                # print(json_output)
                score = predict_score(packet_info, "udp")
                print("UDP Data Score:", score)
                max_index = np.argmax(score[0])
                print(defines[max_index])
                if max_index == 1:
                    print(ip_src)
                    if is_local_ip(ip_src):
                        pass
                    else:
                        block_ip(ip_src)
            else:
                # print("No UDP payload found in packet.")
                pass
        else:
            print("Unknown protocol found in packet.")
    else:
        print("No IP layer found in packet.")


sniff(prn=packet_callback, filter="ip and (tcp or udp)", store=0)
