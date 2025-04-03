import subprocess
import json
from return_file import download_file
import requests


def parse_tshark_output(pcap_file):
    # Commande tshark
    command = [
        "tshark", "-r", pcap_file, "-Y", "http.request",
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "http.request.uri"
    ]
    
    try:
        # Exécuter la commande et capturer la sortie
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Traiter la sortie ligne par ligne
        data = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split("\t")  # Les champs sont séparés par des tabulations
            if len(parts) == 3 and parts[2] != "*":  # Ignorer les entrées où file_requested est "*"
                entry = {"ip_src": parts[0], "ip_dst": parts[1], "file_requested": parts[2]}
                data.append(entry)
        
        return data
    
    except subprocess.CalledProcessError as e:
        return json.dumps({"error": "Erreur lors de l'exécution de tshark", "details": str(e)})


def analyze_malware(pcap_file):
    data = parse_tshark_output(pcap_file)
    malware_analyze = {}
    for result in data:
        ip_dst = result["ip_dst"]
        analysis_api = f"http://127.0.0.1:5000/threat_score/{ip_dst}"
        response = requests.get(analysis_api)
        response.raise_for_status()
        results = response.json()
        str_ip = str(ip_dst)
        if results != []:
            malware_analyze[str_ip] = {"malware" : result["file_requested"]}
    return malware_analyze