from collections import defaultdict

atypical_ports = [445, 3389, 22]  # SMB, RDP, SS

def check_lateral_movement(packets) -> dict:
    analysis = defaultdict(list)
    connections = defaultdict(lambda: defaultdict(int))
    
    for p in packets:
        src_ip = p.get("src_ip")
        dst_ip = p.get("dst_ip")
        port = p.get("port")
        
        if port in atypical_ports:
            connections[src_ip][dst_ip] += 1
            
            if connections[src_ip][dst_ip] > 3:
                existing_entry = next((entry for entry in analysis[src_ip] if entry["dst_ip"] == dst_ip and entry["port"] == port), None)
                
                if existing_entry:
                    existing_entry["count"] = connections[src_ip][dst_ip]
                else:
                    analysis[src_ip].append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": port,
                        "service": "Atype Port" if port in atypical_ports else "Unknown",
                        "count": connections[src_ip][dst_ip]
                    })
    
    return dict(analysis)
