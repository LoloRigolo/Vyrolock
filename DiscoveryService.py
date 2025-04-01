from collections import defaultdict

def check_discovery(packets) -> dict:
    analysis = defaultdict(list)
    icmp_count = defaultdict(int)
    dns_queries = defaultdict(int)

    for p in packets:
        port = p.get("port")
        src_ip = p.get("src_ip")
        dst_ip = p.get("dst_ip")
        
        if port == 53:
            dns_queries[dst_ip] += 1
            analysis[dst_ip].append({
                "src_ip": src_ip,
                "service": "DNS",
                "port": port,
                "query": p.get("payload")[:100]
            })

        if p.get("type") == 8:
            icmp_count[dst_ip] += 1
            analysis[dst_ip].append({
                "src_ip": src_ip,
                "service": "ICMP",
                "port": None,
                "payload": "Ping request"
            })
    
    return dict(analysis)
