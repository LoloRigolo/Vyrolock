suspicious_ports = {22: "SSH", 3389: "RDP"}
suspicious_keywords = ["root", "admin", "sudo"]

def check_privilege_escalation(packets)-> dict:
    analysis: dict = {}
    for p in packets:
        port: str = p.get("port")
        payload: str = p.get("payload", "").lower()
        
        if port in suspicious_ports and any(kw in payload for kw in suspicious_keywords):
            analysis.append({
                "src_ip": p.get("src_ip"),
                "dst_ip": p.get("dst_ip"),
                "port": port,
                "service": suspicious_ports[port],
                "payload": payload[:100]
            })
    
    return analysis
