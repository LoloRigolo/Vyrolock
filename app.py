from flask import Flask, jsonify
from flask_cors import CORS
from return_file import download_file
from initial_acces_service import envoyer_donnees_pcap, extract_pcap_info
from ip_private_connections import analyze_pcap_and_ip
import json
from loguru import logger
from certificate_detection import pcap_to_json
from countryCode import get_country_info, format_json
from check_ip import threat_score
from map_api import map_generator
from ip_connections import public_access
from ip_public_analyze import  get_ip_analysis
from appli_request import analyze_malware, parse_tshark_output

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
        print(data)
        flag = envoyer_donnees_pcap(data)
        if flag != "Flag non trouvé":
            return jsonify({"message": flag, "initial_access" :data})
    return jsonify({"message": "test"})


@app.route('/private_access/<ip_address>', methods=['GET'])
def get_info(ip_address):
    file_path: str = download_file()
    data = analyze_pcap_and_ip(file_path, ip_address)
    return jsonify(data)

@app.route('/public_access/<ip_address>', methods=['GET'])
def get_public_info(ip_address):
    file_path: str = download_file()
    data = public_access(file_path, ip_address)
    return jsonify(data)

@app.route('/map', methods=['GET'])
def map_service():
    file_path: str = download_file()
    response = pcap_to_json(file_path)
    response = format_json(response)
    return jsonify(response)

@app.route('/codeiso/<alpha2>', methods=['GET'])
def iso_service(alpha2):
    response = get_country_info(alpha2)
    return jsonify(response)

@app.route('/threat_score/<ip>', methods=['GET'])
def check_threat_score(ip):
    response = threat_score(ip)
    return jsonify(response)

@app.route('/map2', methods=['GET'])
def map2_service():
    file_path: str = download_file()
    map_generator(file_path)
    return jsonify({"message": "test"})

@app.route('/suspicious', methods=['GET'])
def suspicious_service():
    data = get_ip_analysis()
    return jsonify(data)

@app.route('/malware', methods=['GET'])
def malware_service():
    file_path: str = download_file()
    data = analyze_malware(file_path)
    return jsonify(data)

@app.route('/malware/list', methods=['GET'])
def malware_list_service():
    file_path: str = download_file()
    data = parse_tshark_output(file_path)
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)