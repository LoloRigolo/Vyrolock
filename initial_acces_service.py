import requests
import subprocess
import json

def envoyer_donnees_pcap(data):
    url = "http://93.127.203.48:5000/pcap/submit"
    
    payload = {
        "user_id": "lcesanar",
        "lines": [
            data.get("mac_address"),
            data.get("ip"),
            data.get("nom_machine"),
            data.get("nom_utilisateur")
        ]
    }

    response = requests.post(url, json=payload)
    response_data = response.json()
    print(response_data)
    flag = response_data.get("flag", "Flag non trouvé")
    return flag


def extract_pcap_info(pcap_file: str) -> json:

    tshark_command = [
        r"C:\Program Files\Wireshark\tshark.exe", 
        "-r", pcap_file, 
        "-Y", "ip.src || ip.dst || kerberos", 
        "-T", "fields", 
        "-e", "ip.src", 
        "-e", "ip.dst", 
        "-e", "kerberos.CNameString",  # Nom d'utilisateur Kerberos
        "-e", "kerberos.addr_nb",      # Nom de machine via NetBIOS Name Service (NBNS)
        "-e", "eth.src",               # Adresse MAC source
        "-e", "eth.dst"                # Adresse MAC destination
    ]
    
    process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if stderr:
        raise RuntimeError(f"Erreur: {stderr.decode()}")
    
    lines = stdout.decode().splitlines()
    ip_to_info = {}
    
    for line in lines:
        parts = line.split("\t")
        ip_src = parts[0] if len(parts) > 0 and parts[0] else None
        ip_dst = parts[1] if len(parts) > 1 and parts[1] else None
        cname = parts[2] if len(parts) > 2 and parts[2] and "desktop" not in parts[2].lower() else None
        nbns_name = parts[3] if len(parts) > 3 and parts[3] else None
        mac_src = parts[4] if len(parts) > 4 and parts[4] else None
        mac_dst = parts[5] if len(parts) > 5 and parts[5] else None
        
        if ip_src:
            if ip_src not in ip_to_info:
                ip_to_info[ip_src] = {"nom_utilisateur": "N/A", "nom_machine": "N/A", "mac_address": "N/A"}
            if cname:
                ip_to_info[ip_src]["nom_utilisateur"] = cname
            if nbns_name:
                ip_to_info[ip_src]["nom_machine"] = nbns_name
            if mac_src:
                ip_to_info[ip_src]["mac_address"] = mac_src
        
        if ip_dst:
            if ip_dst not in ip_to_info:
                ip_to_info[ip_dst] = {"nom_utilisateur": "N/A", "nom_machine": "N/A", "mac_address": "N/A"}
            if cname:
                ip_to_info[ip_dst]["nom_utilisateur"] = cname
            if nbns_name:
                ip_to_info[ip_dst]["nom_machine"] = nbns_name
            if mac_dst:
                ip_to_info[ip_dst]["mac_address"] = mac_dst
    
    output_list = [
        {
            "ip": ip,
            "nom_utilisateur": info["nom_utilisateur"],
            "nom_machine": info["nom_machine"],
            "mac_address": info["mac_address"]
        } 
        for ip, info in ip_to_info.items()
        if not (info["nom_utilisateur"] == "N/A" and info["nom_machine"] == "N/A")
    ]
    
    return json.dumps(output_list, indent=4)