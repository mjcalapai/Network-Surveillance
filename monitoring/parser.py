#GPT generated boiler plate code to start off the parser.py 

"""Parses a PCAP file to extract packet-level features and flags basic suspicious activity.

Features extracted:
- timestamp: Epoch timestamp of packet
- src_ip, dst_ip: Source and destination IP addresses
- src_port, dst_port: Source and destination ports
- protocol: Transport layer protocol (TCP/UDP/ICMP/etc)
- length: Packet length in bytes
- flags: TCP flags (if applicable)
- suspicious_flag: True if TCP SYN without ACK (possible port scan)
- suspicious_port: True if dst_port is in common suspicious ports

Outputs:
- CSV file with records
- JSON file with records
"""


import pyshark
import argparse
import json
import csv

# Define a set of ports often used for suspicious activity
SUSPICIOUS_PORTS = {23, 445, 3389, 4444}

def parse_pcap(file_path):
    """
    Load and parse packets from a PCAP file.
    Returns: List of dictionaries, one per packet.
    """
    # Use FileCapture for batch parsing; keep_packets=False to reduce memory usage
    cap = pyshark.FileCapture(file_path, keep_packets=False)
    records = []

    for pkt in cap:
        try:
            # Extract timestamp
            ts = float(pkt.sniff_timestamp)

            # Determine protocol (fallback to highest layer if no transport_layer)
            protocol = pkt.transport_layer or pkt.highest_layer

            # Handle IP layer (IPv4 or IPv6)
            if hasattr(pkt, 'ip'):
                ip_layer = pkt.ip
            elif hasattr(pkt, 'ipv6'):
                ip_layer = pkt.ipv6
            else:
                continue

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Extract ports if applicable
            if protocol in ['TCP', 'UDP']:
                layer = pkt[protocol]
                src_port = layer.srcport
                dst_port = layer.dstport
            else:
                src_port = ''
                dst_port = ''

            # Packet length
            length = int(pkt.length)

            # TCP flags (empty for non-TCP)
            flags = getattr(pkt[protocol], 'flags', '')

            # Flag suspicious SYN without ACK (simple port scan heuristic)
            suspicious_flag = False
            if protocol == 'TCP' and 'SYN' in flags and 'ACK' not in flags:
                suspicious_flag = True

            # Flag suspicious ports
            suspicious_port = False
            if dst_port and int(dst_port) in SUSPICIOUS_PORTS:
                suspicious_port = True

            # Build the record
            record = {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'length': length,
                'flags': flags,
                'suspicious_flag': suspicious_flag,
                'suspicious_port': suspicious_port
            }
            records.append(record)

        except Exception:
            # Skip any packet that raises parsing errors
            continue

    cap.close()
    return records


def save_to_csv(records, output_file):
    """
    Write list of dicts to a CSV file.
    """
    if not records:
        return
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)


def save_to_json(records, output_file):
    """
    Write list of dicts to a JSON file.
    """
    with open(output_file, 'w') as f:
        json.dump(records, f, indent=2)


def main():
    parser = argparse.ArgumentParser(description='Parse PCAP and extract features')
    parser.add_argument('pcap_file', help='Path to the PCAP file')
    parser.add_argument('--csv', default='output.csv', help='Path to CSV output')
    parser.add_argument('--json', default='output.json', help='Path to JSON output')
    args = parser.parse_args()

    print(f'Parsing PCAP: {args.pcap_file}')
    records = parse_pcap(args.pcap_file)
    print(f'Extracted {len(records)} records.')

    if records:
        save_to_csv(records, args.csv)
        print(f'CSV saved to {args.csv}')
        save_to_json(records, args.json)
        print(f'JSON saved to {args.json}')
    else:
        print('No records to save.')

if __name__ == '__main__':
    main()