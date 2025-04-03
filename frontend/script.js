document.addEventListener("DOMContentLoaded", () => {
  const mapDiv = document.getElementById("map");
  if (!mapDiv) {
    return console.error("L'élément #map est introuvable.");
  }

  let map = L.map(mapDiv).setView([51.505, -0.09], 2);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution:
      '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
  }).addTo(map);

  // Fonction de ping
  const pingIP = (ip, callback) => {
    const ping = new Ping();
    ping.ping(ip, (data) => callback(ip, data.avg));
  };

  // Mise à jour des infos IP
  const updateIpInfo = (country, ip) => {
    const ipInfoElement = document.getElementById("ipInfo");
    if (!ipInfoElement) return;

    const ipElement = document.createElement("p");
    ipElement.textContent = `${country}: ${ip}`;
    ipInfoElement.appendChild(ipElement);

    pingIP(ip, (ip, pingTime) => {
      const pingElement = document.createElement("p");
      pingElement.textContent = `Ping pour ${ip}: ${pingTime} ms`;
      ipInfoElement.appendChild(pingElement);
    });
  };

  // Fonction pour obtenir les informations du pays via l'API /codeiso/{alpha2}
  const getCountryInfo = async (countryCode) => {
    try {
      const response = await fetch(
        `http://127.0.0.1:5000/codeiso/${countryCode}`
      );
      const data = await response.json();
      if (data && data.alpha2) {
        return {
          name: data.country,
          lat: data.latitude,
          lon: data.longitude,
        };
      }
    } catch (err) {
      console.error(`Erreur chargement données pays pour ${countryCode}:`, err);
    }
    return null;
  };

  // Fonction pour récupérer les données de la carte
  const fetchMapData = async () => {
    try {
      const response = await fetch("http://127.0.0.1:5000/map");
      const data = await response.json();

      // Traiter chaque pays dans la réponse de la carte
      for (const [countries, ips] of Object.entries(data)) {
        const countryCodes = countries.split(","); // Séparer les pays multiples (ex: "GB,US")

        for (const countryCode of countryCodes) {
          const countryInfo = await getCountryInfo(countryCode.trim()); // Récupérer info pour chaque pays

          if (countryInfo) {
            const { name, lat, lon } = countryInfo;

            ips.forEach((ip) => {
              updateIpInfo(name, ip);
              L.marker([lat, lon]).addTo(map).bindPopup(`${name}: ${ip}`);
            });
          }
        }
      }
    } catch (err) {
      console.error("Erreur chargement données map:", err);
    }
  };

  // Récupérer les données d'accès initial
  const fetchFlagData = async () => {
    try {
      const response = await fetch("http://127.0.0.1:5000/init_access");
      const data = await response.json();
      const { ip, mac_address, nom_machine, nom_utilisateur } =
        data.initial_access;

      document.getElementById("ip").textContent = `IP: ${ip}`;
      document.getElementById("mac").textContent = `MAC: ${mac_address}`;
      document.getElementById(
        "machine"
      ).textContent = `Nom Machine: ${nom_machine}`;
      document.getElementById(
        "user"
      ).textContent = `Utilisateur: ${nom_utilisateur}`;
      document.getElementById("flag").textContent = `Flag: ${data.message}`;
    } catch (err) {
      console.error("Erreur chargement init_access:", err);
    }
  };

  // Initialiser les données de la carte et les données d'accès
  fetchMapData();
  fetchFlagData();
});
