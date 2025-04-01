import subprocess
import json
from loguru import logger

# Fichier PCAP fourni
pcap_file = "ex4.pcap"

# Exécution de la commande tshark pour extraire les adresses IP source, destination, les noms d'utilisateur Kerberos et l'adresse de la machine
tshark_command = [
    "tshark", 
    "-r", pcap_file, 
    "-Y", "ip.src || ip.dst", 
    "-T", "fields", 
    "-e", "ip.src", 
    "-e", "ip.dst", 
    "-e", "kerberos.CNameString",  # Nom d'utilisateur Kerberos
    "-e", "kerberos.addr_nb"        # Adresse de la machine (kerberos.addr_nb)
]

# Lancer la commande tshark et récupérer la sortie
process = subprocess.Popen(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = process.communicate()

# Si une erreur s'est produite, afficher l'erreur et arrêter le script
if stderr:
    print(f"Erreur: {stderr.decode()}")
    exit(1)

# Traitement des résultats
lines = stdout.decode().splitlines()

# Un dictionnaire pour stocker les IP et les informations associées
ip_to_info = {}

for line in lines:
    parts = line.split("\t")  # Séparer les champs selon Tabulation
    ip_src = parts[0] if len(parts) > 0 and parts[0] else None
    ip_dst = parts[1] if len(parts) > 1 and parts[1] else None
    cname = parts[2] if len(parts) > 2 and parts[2] else None
    addr_nb = parts[3] if len(parts) > 3 and parts[3] else None  # Adresse de la machine via Kerberos.addr_nb

    # Utiliser `addr_nb` comme nom de la machine ou "N/A" si l'adresse est vide
    machine_name = addr_nb if addr_nb else "N/A"

    # Traiter l'IP source
    if ip_src:
        if cname:
            # Si un nom d'utilisateur est trouvé, associer un nom de machine si possible
            ip_to_info[ip_src] = {"nom_utilisateur": cname, "nom_machine": machine_name}
        elif ip_src not in ip_to_info:
            ip_to_info[ip_src] = {"nom_utilisateur": "N/A", "nom_machine": "N/A"}

    # Traiter l'IP destination
    if ip_dst:
        if cname:
            # Si un nom d'utilisateur est trouvé, associer un nom de machine si possible
            ip_to_info[ip_dst] = {"nom_utilisateur": cname, "nom_machine": machine_name}
        elif ip_dst not in ip_to_info:
            ip_to_info[ip_dst] = {"nom_utilisateur": "N/A", "nom_machine": "N/A"}

# Créer une liste de dictionnaires avec le format voulu
output_list = [{"ip": ip, "nom_utilisateur": info["nom_utilisateur"], "nom_machine": info["nom_machine"]} 
               for ip, info in ip_to_info.items()]

# Convertir en JSON et imprimer ou enregistrer dans un fichier
json_output = json.dumps(output_list, indent=4)
print(json_output)

# # Optionnel : enregistrer dans un fichier JSON
# with open("output.json", "w") as json_file:
#     json_file.write(json_output)
