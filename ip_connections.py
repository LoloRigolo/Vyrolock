import subprocess
import json
import ipaddress

# Adresse IP source spécifique à surveiller
IP_SRC = "172.17.8.109"

# Liste des IPs de confiance (par exemple, Microsoft, Google, AWS, etc.)
TRUSTED_IPS = [
    "13.107.246.45",  # Exemple : IP Microsoft
    "172.217.0.0",    # Exemple : IP Google
    "8.8.8.8",        # Exemple : DNS Google
    "54.239.28.85",   # Exemple : AWS
]

# Fonction pour vérifier si une IP est publique
def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Vérifie si l'IP n'est pas dans une plage privée
        if ip_obj.is_private:
            return False
        return True
    except ValueError:
        # Si l'IP n'est pas valide, retourne False
        return False

# Fonction pour récupérer les paquets à partir d'un fichier pcap avec tshark
def extract_packets(pcap_file):
    # Exécute tshark pour analyser les paquets avec un filtre spécifique
    command = [
        "tshark", "-r", pcap_file, "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto", "-e", "tcp.port", "-e", "udp.port"
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print("Erreur lors de l'exécution de tshark.")
        return []
    return result.stdout.splitlines()

# Fonction pour filtrer les connexions de l'IP source spécifique vers des IPs publiques
def filter_specific_ip_to_public(packets, ip_src):
    specific_ip_to_public_connections = {}

    for packet in packets:
        fields = packet.split("\t")
        if len(fields) < 4:
            continue
        
        src_ip = fields[0]
        dst_ip = fields[1]
        protocol = fields[2]
        port_field = fields[3] if len(fields) > 3 else None

        # Vérifier si l'IP source correspond à l'IP spécifique et l'IP destination est publique
        if src_ip == ip_src and is_public_ip(dst_ip) and not is_public_ip(src_ip):
            # Ajouter l'IP source spécifique et l'IP destination publique dans le dictionnaire
            if src_ip not in specific_ip_to_public_connections:
                specific_ip_to_public_connections[src_ip] = {}

            # Si l'IP destination n'est pas encore enregistrée, on l'ajoute
            if dst_ip not in specific_ip_to_public_connections[src_ip]:
                specific_ip_to_public_connections[src_ip][dst_ip] = {
                    "nb_tentatives": 0,
                    "ports": set()
                }

            # Mise à jour des informations : tentative de connexion et ports
            specific_ip_to_public_connections[src_ip][dst_ip]["nb_tentatives"] += 1
            if port_field:
                # Séparer les ports si plusieurs sont listés
                ports = port_field.split(',')
                for port in ports:
                    specific_ip_to_public_connections[src_ip][dst_ip]["ports"].add(port.strip())

    # Convertir les sets de ports en listes sans doublons et trier les ports par ordre croissant
    for src_ip in specific_ip_to_public_connections:
        for dst_ip in specific_ip_to_public_connections[src_ip]:
            specific_ip_to_public_connections[src_ip][dst_ip]["ports"] = sorted(
                list(specific_ip_to_public_connections[src_ip][dst_ip]["ports"]),
                key=int  # Trier les ports en tant qu'entiers
            )

    return specific_ip_to_public_connections

# Fonction pour formater les résultats en JSON
def format_to_json(connections):
    # Création du format demandé pour chaque entrée
    formatted_results = []
    for src_ip, dst_ips in connections.items():
        for dst_ip, data in dst_ips.items():
            formatted_results.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "nb_tentatives": data["nb_tentatives"],
                "port": ",".join(map(str, data["ports"]))  # Liste des ports sous forme de string
            })
    return json.dumps(formatted_results, indent=4)

def main(pcap_file):
    # Étape 1 : Extraire les paquets du fichier .pcap
    packets = extract_packets(pcap_file)

    # Étape 2 : Filtrer les connexions de l'IP source spécifique vers les IPs publiques
    connections = filter_specific_ip_to_public(packets, IP_SRC)

    # Étape 3 : Formater les résultats en JSON
    result_json = format_to_json(connections)

    # Afficher le résultat
    print(result_json)


# Si le fichier est exécuté directement, commence à analyser
if __name__ == "__main__":
    # Remplace 'example.pcap' par le chemin de ton fichier .pcap
    pcap_file = "ex4.pcap"
    main(pcap_file)
