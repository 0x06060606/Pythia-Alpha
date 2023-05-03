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


# TODO: Add more features to the model.
class Pythia:  # The Oracle of Delphi
    def __init__(self):
        self.Labels = [
            "Normal Traffic",
            "Remote Connection Traffic",
        ]  # 0 = Normal, 1 = Remote Connection

    def is_local_ip(self, ip: str):
        return ipaddress.ip_address(
            ip
        ).is_private  # Returns True if IP is private, False if public.

    def block_ip(self, ip: str):
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True
            )  # Block IP with iptables.
            print(f" [@] Successfully blocked IP: {ip}")
        except subprocess.CalledProcessError:
            print(f" [@] Failed to block IP: {ip}")

    def hash_data(self, df: pd.DataFrame):
        return df.apply(
            lambda x: int(
                str(
                    int.from_bytes(
                        hashlib.sha256(x.encode("utf-8")).digest(),
                        byteorder="big",
                        signed=False,
                    )
                )[:38]
            )
        )  # Hash data using SHA256 and return the first 38 digits of the hash.

    def preprocess_data(self, df: pd.DataFrame):  # Preprocess data for model.
        df["Payload_length"] = df["Payload"].apply(len)
        df["Source IP"] = self.hash_data(df["Source IP"])
        df["Destination IP"] = self.hash_data(df["Destination IP"])
        df["Hash"] = self.hash_data(df["Hash"])
        df["Payload"] = self.hash_data(df["Payload"])
        df["Type"] = df["Type"].astype("category").cat.codes
        df["Protocol"] = df["Protocol"].astype("category").cat.codes
        print(df)
        df = pd.get_dummies(df, columns=["Protocol"])
        X = df.drop("label", axis=1)
        Y = df["label"]
        return (df, X, Y)  # Return preprocessed data, X, and Y.

    def predict_score(
        self, new_data: dict, dat_type: str
    ):  # Predict score of new data.
        model = joblib.load("models/" + dat_type + ".pkl")
        new_data = pd.DataFrame(new_data, index=[0])
        preprocessed_data, X, Y = self.preprocess_data(new_data)
        prediction = model.predict_proba(preprocessed_data)
        return prediction  # Return prediction.

    def packet_callback(
        self, packet: scapy.packet.Packet
    ):  # Callback function for sniffing packets.
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
                    # json_output = json.dumps(packet_info)
                    # print(json_output)
                    score = self.predict_score(packet_info, "tcp")
                    print("TCP Data Score:", score)
                    max_index = np.argmax(score[0])
                    print(self.defines[max_index])
                    if max_index == 1:
                        print(ip_src)
                        if self.is_local_ip(ip_src):
                            pass  # Do nothing
                        else:
                            self.block_ip(ip_src)
                else:
                    pass  # No TCP payload found in packet.
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
                    # json_output = json.dumps(packet_info)
                    # print(json_output)
                    score = self.predict_score(packet_info, "udp")
                    print("UDP Data Score:", score)
                    max_index = np.argmax(score[0])
                    print(self.defines[max_index])
                    if max_index == 1:
                        print(ip_src)
                        if self.is_local_ip(ip_src):
                            pass  # Do nothing
                        else:
                            self.block_ip(ip_src)
                else:
                    pass  # No UDP payload found in packet.
            else:
                pass  # No TCP or UDP layer found in packet.
        else:
            pass  # No IP layer found in packet.

    def start_sniff(self):  # Start sniffing packets.
        print(" [#] Starting Pythia Sniffer...")
        sniff(
            prn=self.packet_callback, filter="ip and (tcp or udp)", store=0
        )  # Sniff packets and call packet_callback() for each packet.

    def spawn_dataframe(self, data: str):  # Spawn dataframe from JSON data.
        formatted_data = []
        data = json.load(data)
        for entry in data:
            entry_data = json.loads(entry["data"])
            entry_data["label"] = entry["label"]
            formatted_data.append(entry_data)
        return pd.DataFrame(formatted_data)  # Return dataframe.

    def train_model(self, X: pd.DataFrame, y: pd.Series):  # Train model.
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )  # Split data into training and testing sets.
        clf = RandomForestClassifier(random_state=42)  # Create model.
        clf.fit(X_train, y_train)  # Fit model.
        return (clf, X_test, y_test)  # Return model, X_test, and y_test.

    def finish_model(
        self, clf: RandomForestClassifier, X_test, y_test, dat_type: str
    ):  # Finish model.
        joblib.dump(clf, "models/" + dat_type + ".pkl")  # Save model.
        predictions = clf.predict(X_test)  # Make predictions.
        accuracy = accuracy_score(y_test, predictions)  # Calculate accuracy.
        print(dat_type + " Accuracy: ", accuracy)  # Print accuracy.
        print(
            dat_type + " Confusion Matrix: ", confusion_matrix(y_test, predictions)
        )  # Print confusion matrix.
        print(
            dat_type + " Classification Report: ",
            classification_report(y_test, predictions),
        )  # Print classification report.
        return accuracy  # Return accuracy.

    def start_model(self, data_type: str):  # Start model.
        with open("data/" + data_type + ".json") as f_in:  # Open JSON file.
            df = self.spawn_dataframe(f_in)  # Spawn dataframe.
            df, X, y = self.preprocess_data(df)  # Preprocess data.
            clf, X_test, y_test = self.train_model(X, y)  # Train model.
            return self.finish_model(clf, X_test, y_test, data_type)  # Finish model.
