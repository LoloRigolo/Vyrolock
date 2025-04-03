import json

def get_country_info(alpha2_code, file_path="countryCode.json"):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            
            for country in data.get("ref_country_codes", []):
                if country.get("alpha2") == alpha2_code.upper():
                    return country
                elif country.get("alpha3")== alpha2_code.upper():
                    return country
            return f"Aucune information trouvée pour le code : {alpha2_code}"
    except Exception as e:
        return f"Erreur lors de la lecture du fichier : {e}"

