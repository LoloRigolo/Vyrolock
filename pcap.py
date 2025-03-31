import os
import subprocess
from collections import Counter

# Définir le fichier PCAP
pcap_file = "ex4.pcap"

# Vérifier si le fichier existe
if not os.path.exists(pcap_file):
    print("❌ Fichier PCAP non trouvé ! Vérifie le chemin.")
    exit()

# Fonction pour exécuter `tshark` et capturer les sorties
def run_tshark(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout.strip().split("\n")
        return [line for line in output if line]  # Supprime les lignes vides
    except Exception as e:
        print(f"❌ Erreur lors de l'exécution de la commande : {command}")
        print(e)
        return []

# Commandes `tshark` adaptées pour Windows
commands = {
    "IPs Communicantes": f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst -E separator=,",
    "Requêtes DNS": f"tshark -r {pcap_file} -Y dns -T fields -e dns.qry.name -E separator=,",
    "Requêtes HTTP": f"tshark -r {pcap_file} -Y http.request -T fields -e ip.src -e http.host -E separator=,",
    "Scan Réseau": f"tshark -r {pcap_file} -Y \"tcp.flags.syn == 1 and tcp.flags.ack == 0\" -T fields -e ip.src -E separator=,"
}

# Exécuter les commandes et afficher les résultats
for title, cmd in commands.items():
    print(f"\n🔍 {title} :\n" + "-" * 40)
    output = run_tshark(cmd)

    if not output:
        print("⚠️ Aucune donnée trouvée.")
        continue

    if "IPs Communicantes" in title:
        counter = Counter(output)
        for item, count in counter.most_common():
            print(f"📡 {item} → {count} fois")

    elif "Requêtes DNS" in title or "Requêtes HTTP" in title:
        for entry in sorted(set(output)):
            print(f"🌍 {entry}")

    else:  # Scan Réseau
        for line in output:
            print(f"🚨 Scan détecté depuis {line}")
