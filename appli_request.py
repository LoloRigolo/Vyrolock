import subprocess
import json
from return_file import download_file


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
        
        # Convertir en JSON
        return json.dumps(data, indent=4)
    
    except subprocess.CalledProcessError as e:
        return json.dumps({"error": "Erreur lors de l'exécution de tshark", "details": str(e)})

# Exemple d'utilisation
pcap_file = download_file()  # Remplace par le bon chemin si nécessaire
json_output = parse_tshark_output(pcap_file)
print(json_output)
