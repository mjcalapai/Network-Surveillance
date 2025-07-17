#GPT generated boiler plate code to start off the parser.py 

import argparse
import logging
import os
import subprocess
import json

import pyshark  # for pcap parsing
import pandas as pd  # for training data
from sklearn.externals import joblib  # or pickle for ML models

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

def parse_args():
    parser = argparse.ArgumentParser(description="Network traffic parser & analyzer")
    parser.add_argument('--pcap', help='Path to pcap file')
    parser.add_argument('--training-data', help='Path to CSV/JSON training data')
    parser.add_argument('--ml-model', help='Path to ML model file (.pkl)')
    return parser.parse_args()

def run_suricata(pcap_path):
    """Run Suricata on pcap and parse eve.json"""
    logging.info(f"Running Suricata on {pcap_path}")
    subprocess.run(['suricata', '-r', pcap_path, '-l', './suricata_output'], check=True)

    events = []
    with open('./suricata_output/eve.json') as f:
        for line in f:
            event = json.loads(line)
            events.append(event)
    return events

def run_zeek(pcap_path):
    """Run Zeek on pcap and parse conn.log"""
    logging.info(f"Running Zeek on {pcap_path}")
    subprocess.run(['zeek', '-r', pcap_path], check=True)

    conn_log = pd.read_csv('conn.log', sep='\t', comment='#', low_memory=False)
    return conn_log

def load_ml_model(model_path):
    """Load ML model"""
    logging.info(f"Loading ML model from {model_path}")
    return joblib.load(model_path)

def analyze_with_ml(model, data):
    """Run ML model on DataFrame `data`"""
    predictions = model.predict(data)
    return predictions

def process_pcap(pcap_path):
    """Process pcap file with pyshark"""
    logging.info(f"Parsing pcap with pyshark: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path)
    packets = []
    for pkt in cap:
        packets.append(pkt)  # or extract features
    cap.close()
    return packets

def process_training_data(data_path):
    """Load training data"""
    logging.info(f"Loading training data: {data_path}")
    if data_path.endswith('.csv'):
        df = pd.read_csv(data_path)
    elif data_path.endswith('.json'):
        df = pd.read_json(data_path)
    else:
        raise ValueError("Unsupported training data format")
    return df

def main():
    args = parse_args()

    if args.pcap:
        packets = process_pcap(args.pcap)

        suricata_results = run_suricata(args.pcap)
        zeek_results = run_zeek(args.pcap)

        # Optional: transform packets to ML-ready format and predict
        # features_df = extract_features(packets)
        # if args.ml_model:
        #     ml_model = load_ml_model(args.ml_model)
        #     ml_results = analyze_with_ml(ml_model, features_df)

    elif args.training_data:
        training_df = process_training_data(args.training_data)
        if args.ml_model:
            ml_model = load_ml_model(args.ml_model)
            predictions = analyze_with_ml(ml_model, training_df)
            print(predictions)
    else:
        logging.error("You must specify either --pcap or --training-data")
        exit(1)

if __name__ == '__main__':
    main()