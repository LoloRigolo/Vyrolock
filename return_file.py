import subprocess
import os
import requests

def download_file(dest_folder: str = "./pcap") -> str:
    os.makedirs(dest_folder, exist_ok=True)
    url: str = "http://93.127.203.48:5000/pcap/latest"
    url_filename: str = url + "/filename"
    
    response = requests.get(url_filename)
    if response.status_code == 200:
        data = response.json()
        filename = data.get("filename")
        file_path = os.path.join(dest_folder, filename)

        if os.path.exists(file_path):
            print(f"Le fichier {filename} existe déjà dans {dest_folder}.")
            return file_path
    
    try:
        subprocess.run(["curl", "-OJ", "-sL", "-o", dest_folder, url], check=True, cwd=dest_folder)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Échec du téléchargement depuis {url}")

    downloaded_files = sorted(os.listdir(dest_folder), key=lambda f: os.path.getctime(os.path.join(dest_folder, f)), reverse=True)
    if not downloaded_files:
        raise RuntimeError("Aucun fichier téléchargé trouvé.")

    filename = downloaded_files[0]
    file_path = os.path.join(dest_folder, filename)
    
    return file_path
