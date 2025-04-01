import IpAddressService
import InitialAcessService
import PersistenceService
import json
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

packets = rdpcap("ex4.pcap")

connections = defaultdict(list)

def extract_info(packet):
    """Extraction des informations réseau importantes d'un paquet"""
    data = {}
    
    if packet.haslayer(IP):
        data["src_ip"] = packet[IP].src
        data["dst_ip"] = packet[IP].dst
        data["timestamp"] = packet.time
        if packet.haslayer(TCP):
            data["port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            data["port"] = packet[UDP].dport
        else:
            data["port"] = None
        
        return data
    return None

filtered_packets = [extract_info(p) for p in packets if extract_info(p)]

packets_json = json.dumps(filtered_packets, indent=4, default=str)

result: dict = {}

ips = []
ips_analysis = {}
initials_access_analysis = {}
c2_persistence_analysis = {}

for packet_data in filtered_packets:
    ip = packet_data["dst_ip"]
    port = packet_data["port"]
    timestamp = packet_data["timestamp"]

    initials_access_analysis = InitialAcessService.check_initial_acess(port, initials_access_analysis, ip)
     
    # if ip not in ips:
    #     ips.append(ip)
    #     ip_analysis = IpAddressService.check_sources(ip)
    #     ips_analysis[ip] = ip_analysis

    connections[(packet_data["src_ip"], ip, port)].append(timestamp)

# Persistence Service
for (src_ip, dst_ip, dport), timestamps in connections.items():
    c2_persistence_analysis = PersistenceService.check_persistence(timestamps, c2_persistence_analysis, dst_ip, dport)

result = {
    "ips_analysis": ips_analysis,
    "initials_access_analysis": initials_access_analysis,
    "c2_persistence_analysis": c2_persistence_analysis
}

print(json.dumps(result, indent=4, default=str))
