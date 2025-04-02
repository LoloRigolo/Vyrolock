from flask import Flask, jsonify
from flask_cors import CORS
from return_file import download_file
from initial_acces_service import envoyer_donnees_pcap, extract_pcap_info
from ip_private_connections import analyze_pcap_and_ip
import json
from loguru import logger

app = Flask(__name__)
CORS(app)

@app.route('/file', methods=['GET'])
def get_data():
    file_path: str = download_file()
    return jsonify({"message": file_path})

@app.route('/init_access', methods=['GET'])
def initial_access():
    file_path: str = download_file()
    pcap_info: str = extract_pcap_info(file_path)
    pcap_info = json.loads(pcap_info)
    for data in pcap_info:
        flag = envoyer_donnees_pcap(data)
        if flag != "Flag non trouvé":
            return jsonify({"message": flag, "initial_access" :data})
    return jsonify({"message": "test"})


@app.route('/private_access/<ip_address>', methods=['GET'])
def get_info(ip_address):
    file_path: str = download_file()
    data = analyze_pcap_and_ip(file_path, ip_address)
    return jsonify(data)


if __name__ == '__main__':
    app.run(debug=True)