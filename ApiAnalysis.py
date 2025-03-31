import requests


def virus_total_analysis(ip :str):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "accept": "application/json",
        "x-apikey": "6d3072a3909d8e79246b894689632f07912af9b144c81012cf4fd1f371a27a9a"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return last_analysis_stats
    else:
        return {}

