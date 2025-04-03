import requests

def moyenne(tableau):
    return sum(tableau) / len(tableau) if tableau else 0

def get_data():
    response = requests.get("http://127.0.0.1:5000/init_access")
    return response.json()
def data_to_ip(data):
    ip = data["initial_access"]["ip"]
    return ip

def get_ip_analysis():
    info = get_data()
    ip = data_to_ip(info)
    """ Récupère les IPs accessibles et analyse chacune d'elles. """
    public_access_api = f"http://127.0.0.1:5000/public_access/{ip}"
    
    try:
        # Récupération des IPs accessibles
        response = requests.get(public_access_api)
        response.raise_for_status()
        ip_data = response.json()  # Dictionnaire d'IPs accessibles
    except requests.RequestException as e:
        print(f"Erreur lors de la récupération des IPs : {e}")
        return {ip: {"state": "unknown", "threat_score": 0}}

    result_dict = {}

    for target_ip in ip_data.keys():
        analysis_api = f"http://127.0.0.1:5000/threat_score/{target_ip}"
        response = requests.get(analysis_api)
        response.raise_for_status()
        results = response.json()
        str_ip = str(target_ip)
        if results != []:
            result_dict[str_ip] = {"state": "", "threat_score":[]}
            for analyze in results:
                result_dict[str_ip]["threat_score"].append(analyze["threat_score"])
                result_dict[str_ip]["state"] = analyze["verdict"]
            result_dict[str_ip]["threat_score"] = moyenne(result_dict[str_ip]["threat_score"])
    return result_dict

