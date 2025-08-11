#!/usr/bin/env python3
"""
Parse a PCAP into rows + emit simple alerts.

Packet features:
- timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags
Heuristics / alerts:
- possible_port_scan: many SYN (no ACK) to distinct ports/hosts in a short window
- sensitive_port_touch: traffic to ports in SUSPICIOUS_PORTS

Outputs:
- --csv output.csv (rows)
- --json output.json (rows)
- --alerts alerts.jsonl (one JSON object per alert)
"""

import argparse
import csv
import json
from collections import defaultdict
from typing import List, Dict, Any

import pyshark

# Tunables (can later move these to config.yaml)
SUSPICIOUS_PORTS = {22, 23, 445, 3389, 4444}  # SSH, Telnet, SMB, RDP, Metasploit
SCAN_WINDOW_SECONDS = 10
MIN_UNIQUE_PORTS = 20
MIN_UNIQUE_HOSTS = 10


def parse_pcap(file_path: str) -> List[Dict[str, Any]]: #file path mentioned here
    """Load and parse packets from a PCAP file -> list of row dicts."""
    records: List[Dict[str, Any]] = []
    cap = pyshark.FileCapture(file_path, keep_packets=False)  # batch/stream friendly  FACT CHECK FILE PATH HERE

    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)

            # protocol at transport layer if present, else highest layer
            protocol = pkt.transport_layer or pkt.highest_layer

            # IP layer (v4 or v6); skip if neither
            ip_layer = None
            if hasattr(pkt, 'ip'):
                ip_layer = pkt.ip
            elif hasattr(pkt, 'ipv6'):
                ip_layer = pkt.ipv6
            if ip_layer is None:
                continue

            src_ip = getattr(ip_layer, 'src', '')
            dst_ip = getattr(ip_layer, 'dst', '')

            src_port = ''
            dst_port = ''
            if protocol in ('TCP', 'UDP'):
                try:
                    layer = pkt[protocol]
                    src_port = getattr(layer, 'srcport', '') or ''
                    dst_port = getattr(layer, 'dstport', '') or ''
                except Exception:
                    pass

            # packet length
            try:
                length = int(getattr(pkt, 'length', getattr(pkt.frame_info, 'len', 0)))
            except Exception:
                length = 0

            # TCP flags (robust: prefer per-flag bits; fall back to flags_str)
            flags_str = ''
            syn_no_ack = False
            if protocol == 'TCP':
                tcp_layer = pkt.tcp if hasattr(pkt, 'tcp') else None
                if tcp_layer is not None:
                    # per-bit flags exposed as '1' or '0'
                    syn = getattr(tcp_layer, 'flags_syn', '0') == '1'
                    ack = getattr(tcp_layer, 'flags_ack', '0') == '1'
                    syn_no_ack = syn and not ack
                    flags_str = getattr(tcp_layer, 'flags_str', '') or getattr(tcp_layer, 'flags', '')
            else:
                flags_str = ''

            suspicious_flag = bool(syn_no_ack)
            suspicious_port = False
            try:
                if dst_port and int(dst_port) in SUSPICIOUS_PORTS:
                    suspicious_port = True
            except ValueError:
                pass

            records.append({
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'length': length,
                'flags': flags_str,
                'suspicious_flag': suspicious_flag,
                'suspicious_port': suspicious_port
            })
        except Exception:
            # skip parse errors quietly to keep the pipeline moving
            continue

    cap.close()
    return records


def find_scans(records: List[Dict[str, Any]],
               window_seconds: int = SCAN_WINDOW_SECONDS,
               min_unique_ports: int = MIN_UNIQUE_PORTS,
               min_unique_hosts: int = MIN_UNIQUE_HOSTS) -> List[Dict[str, Any]]:
    """
    Sliding-window heuristic:
    - group by src_ip over TCP SYN-without-ACK packets
    - if within window we see many distinct dst ports OR hosts -> alert
    """
    by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        if r.get('protocol') == 'TCP' and r.get('suspicious_flag'):
            by_src[r['src_ip']].append(r)

    alerts = []
    for src, pkts in by_src.items():
        if not src:
            continue
        pkts.sort(key=lambda x: x['timestamp'])
        i = 0
        for j in range(len(pkts)):
            # advance start of window while too wide
            while pkts[j]['timestamp'] - pkts[i]['timestamp'] > window_seconds:
                i += 1
            window = pkts[i:j+1]
            unique_ports = {w['dst_port'] for w in window if w.get('dst_port')}
            unique_hosts = {w['dst_ip'] for w in window if w.get('dst_ip')}
            if len(unique_ports) >= min_unique_ports or len(unique_hosts) >= min_unique_hosts:
                alerts.append({
                    'ts_start': window[0]['timestamp'],
                    'ts_end': window[-1]['timestamp'],
                    'type': 'possible_port_scan',
                    'src_ip': src,
                    'unique_ports': sorted(unique_ports),
                    'unique_hosts_count': len(unique_hosts),
                    'packet_count': len(window),
                    'severity': 'high' if len(unique_ports) >= min_unique_ports else 'medium'
                })
                # optional de-dup: jump i forward slightly to reduce duplicate alerts
    return alerts


def find_sensitive_port_touches(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Emit an alert whenever a packet targets a sensitive port."""
    alerts = []
    for r in records:
        try:
            if r.get('dst_port') and int(r['dst_port']) in SUSPICIOUS_PORTS:
                alerts.append({
                    'ts': r['timestamp'],
                    'type': 'sensitive_port_touch',
                    'src_ip': r.get('src_ip', ''),
                    'dst_ip': r.get('dst_ip', ''),
                    'dst_port': int(r['dst_port']),
                    'protocol': r.get('protocol', ''),
                    'severity': 'medium'
                })
        except ValueError:
            continue
    return alerts


def save_to_csv(records: List[Dict[str, Any]], output_file: str) -> None:
    if not records:
        return
    with open(output_file, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        w.writeheader()
        w.writerows(records)


def save_to_json(records: List[Dict[str, Any]], output_file: str) -> None:
    with open(output_file, 'w') as f:
        json.dump(records, f, indent=2)


def append_alerts_jsonl(alerts: List[Dict[str, Any]], alerts_path: str) -> None:
    if not alerts_path or not alerts:
        return
    with open(alerts_path, 'a') as f:
        for a in alerts:
            f.write(json.dumps(a) + '\n')


def main():
    ap = argparse.ArgumentParser(description='Parse PCAP → rows + alerts.')
    ap.add_argument('pcap_file', help='Path to the PCAP file')
    ap.add_argument('--csv', default='', help='Write rows to CSV path')
    ap.add_argument('--json', default='', help='Write rows to JSON path')
    ap.add_argument('--alerts', default='alerts.jsonl', help='Append alerts to this JSONL file')
    ap.add_argument('--scan-window', type=int, default=SCAN_WINDOW_SECONDS, help='Seconds in scan window')
    ap.add_argument('--scan-ports', type=int, default=MIN_UNIQUE_PORTS, help='Min unique ports for scan alert')
    ap.add_argument('--scan-hosts', type=int, default=MIN_UNIQUE_HOSTS, help='Min unique hosts for scan alert')
    args = ap.parse_args()

    print(f'Parsing PCAP: {args.pcap_file}')
    records = parse_pcap(args.pcap_file)
    print(f'Extracted {len(records)} packet rows.')

    if args.csv:
        save_to_csv(records, args.csv)
        print(f'CSV → {args.csv}')
    if args.json:
        save_to_json(records, args.json)
        print(f'JSON → {args.json}')

    # alerts
    scan_alerts = find_scans(records, args.scan_window, args.scan_ports, args.scan_hosts)
    sens_alerts = find_sensitive_port_touches(records)
    all_alerts = scan_alerts + sens_alerts
    append_alerts_jsonl(all_alerts, args.alerts)
    print(f'Alerts appended: {len(all_alerts)} → {args.alerts}' if all_alerts else 'No alerts emitted.')

if __name__ == '__main__':
    main()
