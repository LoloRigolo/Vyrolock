import subprocess
import json

# Fichier PCAP fourni
pcap_file = "chall_wshark1.pcap"

# Exécution de la commande tshark pour extraire les IP, utilisateurs Kerberos, noms NetBIOS et adresses MAC
tshark_command = [
    "tshark", 
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
    parts = line.split("\t")  # Séparer les champs selon tabulation
    ip_src = parts[0] if len(parts) > 0 and parts[0] else None
    ip_dst = parts[1] if len(parts) > 1 and parts[1] else None
    cname = parts[2] if len(parts) > 2 and parts[2] else None
    nbns_name = parts[3] if len(parts) > 3 and parts[3] else None  # Nom de la machine via NBNS
    mac_src = parts[4] if len(parts) > 4 and parts[4] else None  # MAC source
    mac_dst = parts[5] if len(parts) > 5 and parts[5] else None  # MAC destination

    # Traiter l'IP source
    if ip_src:
        if ip_src not in ip_to_info:
            ip_to_info[ip_src] = {"nom_utilisateur": "N/A", "nom_machine": "N/A", "mac_address": "N/A"}
        if cname:
            ip_to_info[ip_src]["nom_utilisateur"] = cname
        if nbns_name:
            ip_to_info[ip_src]["nom_machine"] = nbns_name
        if mac_src:
            ip_to_info[ip_src]["mac_address"] = mac_src

    # Traiter l'IP destination
    if ip_dst:
        if ip_dst not in ip_to_info:
            ip_to_info[ip_dst] = {"nom_utilisateur": "N/A", "nom_machine": "N/A", "mac_address": "N/A"}
        if cname:
            ip_to_info[ip_dst]["nom_utilisateur"] = cname
        if nbns_name:
            ip_to_info[ip_dst]["nom_machine"] = nbns_name
        if mac_dst:
            ip_to_info[ip_dst]["mac_address"] = mac_dst

# Créer une liste de dictionnaires avec le format voulu (IP → Nom utilisateur → Nom machine → MAC)
output_list = [
    {
        "ip": ip,
        "nom_utilisateur": info["nom_utilisateur"],
        "nom_machine": info["nom_machine"],
        "mac_address": info["mac_address"]
    } 
    for ip, info in ip_to_info.items()
    if not (info["nom_utilisateur"] == "N/A" and info["nom_machine"] == "N/A")  # Filtrer les entrées vides
]

# Convertir en JSON et imprimer ou enregistrer dans un fichier
json_output = json.dumps(output_list, indent=4)
print(json_output)


