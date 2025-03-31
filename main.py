import IpAddressService
import json
from scapy.all import rdpcap, IP, TCP, UDP

packets = rdpcap("ex4.pcap")

def extract_info(packet):
    data = {}
    
    if packet.haslayer(IP):
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst
    
        if packet.haslayer(TCP):
            data["port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            data["port"] = packet[UDP].dport
        else:
            data["port"] = None
            
        return data
    return None

filtered_packets = [extract_info(p) for p in packets if extract_info(p)]

packets_json = json.dumps(filtered_packets, indent=4)

ips = []
ips_analysis = {}

for packet_data in filtered_packets:
    ip = packet_data["dst_ip"]
    port = packet_data["port"]
    
    if ip not in ips:
        ips.append(ip)
        ip_analysis = IpAddressService.check_sources(ip)
        ips_analysis[ip] = ip_analysis

print(json.dumps(ips_analysis, indent=4))
