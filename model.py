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


def spawn_dataframe(data):
    formatted_data = []
    data = json.load(data)
    for entry in data:
        entry_data = json.loads(entry["data"])
        entry_data["label"] = entry["label"]
        formatted_data.append(entry_data)
    df = pd.DataFrame(formatted_data)
    return df


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


def train(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_train, y_train)
    return (clf, X_test, y_test)


def finish(clf, X_test, y_test, dat_type):
    joblib.dump(clf, "model_" + dat_type + ".pkl")
    predictions = clf.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(dat_type + " Accuracy: ", accuracy)


def start(json_file, data_type):
    with open(json_file) as f_in:
        df = spawn_dataframe(f_in)
        df, X, y = preprocess_data(df)
        clf, X_test, y_test = train(X, y)
        finish(clf, X_test, y_test, data_type)


start("data_tcp.json", "tcp")
start("data_udp.json", "udp")
