import IpAddressService
import InitialAcessService
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

result: dict = {}

ips = []
ips_analysis = {}
initials_access_analysis = {}

for packet_data in filtered_packets:
    ip = packet_data["dst_ip"]
    port = packet_data["port"]
    if InitialAcessService.check_initial_acess(port):
        if ip in initials_access_analysis:
            initials_access_analysis[ip]["attempts"] += 1
        else:
            initial_access_analysis = { "port" : [port], "attempts": 1}
            initials_access_analysis[ip] = initial_access_analysis
    
    if ip not in ips:
        ips.append(ip)
        ip_analysis = IpAddressService.check_sources(ip)
        ips_analysis[ip] = ip_analysis

#result = {ips_analysis, initials_access_analysis}
print(json.dumps(initials_access_analysis, indent=4))
