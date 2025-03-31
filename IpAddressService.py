import ipaddress
import ApiAnalysis

def check_ip_address(ip: str) -> bool: 
    if ipaddress.ip_address(ip).is_private:
        return False
    return True

def check_port(port: str) -> bool:
    return port == 443 or port == 80

def check_sources(ip: str) -> dict:
    if (check_ip_address(ip)):
        ip_check: dict = ApiAnalysis.virus_total_analysis(ip)
        return ip_check
    return {}

