import json

def get_country_info(alpha2_code, file_path="countryCode.json"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            
            for country in data.get("ref_country_codes", []):
                if country.get("alpha2") == alpha2_code.upper():
                    return country
                elif country.get("alpha3") == alpha2_code.upper():
                    return country
            return None  # Retourne None si le pays n'est pas trouvé
    except Exception as e:
        print(f"Erreur : {e}")
        return None  # Retourne None en cas d'erreur

def format_json(object_json):
    response = []
    
    # Traiter les codes séparés par des virgules
    iso_list = object_json.split(",") if isinstance(object_json, str) else object_json
    countries_seen = set()  # Pour éviter les doublons

    for iso in iso_list:
        iso = iso.strip()  # Enlever les espaces autour du code ISO
        if iso in countries_seen:  # Vérification pour éviter les doublons
            continue
        
        country_info = get_country_info(iso)  # Enlever les espaces autour du code ISO
        countries_seen.add(iso)  # Marquer ce pays comme vu

        if country_info is None:  # Si le pays est inconnu
            response.append({
                "country": "inconnu", 
                "ip": object_json  # Renvoyer tout le tableau d'IP
            })
        else:
            # Si le pays est trouvé, ajouter les informations
            country_data = {
                "country": country_info.get("country", "Inconnu"),
                "latitude": country_info.get("latitude", "Inconnu"),
                "longitude": country_info.get("longitude", "Inconnu")
            }
            
            if iso.upper() in ["GB", "US"]:
                country_data["special_note"] = "Country requires special processing"
            
            response.append(country_data)

    return {"data": response}