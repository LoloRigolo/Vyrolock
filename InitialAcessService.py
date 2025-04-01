critical_ports = [22, 3389, 21, 23, 445]

def check_initial_acess(port: str, analysis: dict, ip: str) -> dict:
    if port in critical_ports:
        if ip in analysis:
            analysis[ip]["attempts"] += 1
        else:
            initial_access_analysis = {"port": [port], "attempts": 1}
            analysis[ip] = initial_access_analysis
    return analysis