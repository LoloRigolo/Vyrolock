import json
from scapy.all import IP, TCP, Raw

SUSPICIOUS_PATTERNS = [
    b"cmd.exe", b"powershell", b"bash -i", b"nc -e", b"Invoke-Expression",
    b"wget ", b"curl ", b"python -c", b"perl -e", b"php -r", b"ssh -o"
]

def detect_suspicious_commands(filtered_packets):
    suspicious_traffic = {}

    for packet_data in filtered_packets:     
        if "src_ip" not in packet_data or "dst_ip" not in packet_data or "port" not in packet_data:
            continue  

        src_ip = packet_data["src_ip"]
        dst_ip = packet_data["dst_ip"]
        port = packet_data["port"]
        timestamp = packet_data["timestamp"]

        if 'payload' in packet_data:
            payload = (packet_data['payload'])

            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in payload.encode('utf-8'):
                    if src_ip not in suspicious_traffic:
                        suspicious_traffic[src_ip] = []

                    suspicious_traffic[src_ip].append({
                        "dst_ip": dst_ip,
                        "port": port,
                        "payload": payload,
                        "timestamp": timestamp
                    })
                    break  

    return suspicious_traffic


