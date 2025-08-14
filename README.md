1. Introduction:
A Raspberry Pi–based tool for capturing network traffic, detecting suspicious activity (port scans, sensitive port access), and exporting alerts for future visualization and response. For fun, the tool will include a PiHole and will be optimized to run as a home network security lab.

2. Current Features:
   - Captures packets in capture.py using Pyshark/Tshark
         - currently just within a 10 second window upon running and it will save to a pcap file.
   - parser.py parses the packets for
         - Possible Port Scan — many SYN packets to unique ports in a short time window
         - Sensitive Port Access — connection attempts to SSH, Telnet, SMB, RDP, and Metasploit ports
   - Outputs:
         - data.csv — structured packet data
         - data.json — JSON packet data
         - alerts.jsonl — one JSON alert per line

3. Requirement & Installation:
   - This project requires access to Wireshark/Tshark/PyShark version (please fill in soon future Mitchell)
   - git clone https://github.com/mjcalapai/Network-Survaillance.git
     cd Network-Surveillance

4. Usage:
   - Basic Command examples to make this project run
         - Parse a PCAP and export results
             python parser.py --pcap path/to/file.pcap --csv data.csv --json data.json --alerts alerts.jsonl
         - Live capture example (requires root privileges)
             sudo python capture.py --interface eth0

5. How to Trigger Alerts:
   - From another device or instance of the terminal, perform a port scan on a sensitive port lised in parser.py during the instance of capture.py running, for example:
         nmap -p 20-100 <target-ip>
         ssh user@<target-ip>

6. Output Samples:
   - Input Command:
        python monitoring\parser.py .\capture.pcap   --csv data\\processed\\out.csv
        --json data\processed\out.json `
        --alerts data\processed\alerts.jsonl  

    - Terinal Output:
        Parsing PCAP: .\capture.pcap
        Extracted 11703 packet rows.
        CSV → data\\processed\\out.csv
        JSON → data\processed\out.json
        Alerts appended: 3 → data\processed\alerts.jsonl

   - Appended to alerts.jsonl:
         {"ts": 1754925911.81495, "type": "sensitive_port_touch", "src_ip": "192.168.0.21", "dst_ip": "192.168.1.1", "dst_port": 23, "protocol": "TCP", "severity":"medium"}
         {"ts": 1754925915.815037, "type": "sensitive_port_touch", "src_ip": "192.168.0.21", "dst_ip": "192.168.1.1", "dst_port": 23, "protocol": "TCP", "severity":                     "medium"}
        {"ts": 1754925923.828676, "type": "sensitive_port_touch", "src_ip": "192.168.0.21", "dst_ip": "192.168.1.1", "dst_port": 23, "protocol": "TCP", "severity":                     "medium"}

7. Next Steps:
   - My next step is to build out the response system, blocking suspicious IP addresses and notifying myself via email when that occurs. 




   
