let attackObject = [
  {"brutforce":0},
  {"analysePort":0}
];

let globalIp = ""; // variable globale qui stocke l'IP
fetch("http://127.0.0.1:5000/malware")
  .then((response) => response.json())
  .then((data) => {
    const malwareTableBody = document.querySelector("#malware-table tbody");

    // Itérer sur chaque entrée IP et Malware
    Object.entries(data).forEach(([ip, { malware }]) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${ip}</td>
        <td>${malware}</td>
      `;
      malwareTableBody.appendChild(row);
    });
  })
  .catch((error) =>
    console.error("Erreur lors de la récupération des malwares:", error)
  );

fetch("http://127.0.0.1:5000/suspicious")
  .then((response) => response.json())
  .then((data) => {
    // Trier les IPs par 'threat_score' décroissant
    const sortedIps = Object.entries(data).sort(
      (a, b) => b[1].threat_score - a[1].threat_score
    );

    const suspiciousTableBody = document.querySelector(
      "#suspicious-table tbody"
    );

    // Itérer sur les IPs triées et ajouter chaque ligne au tableau
    sortedIps.forEach(([ip, { state, threat_score }]) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${ip}</td>
        <td>${state}</td>
        <td>${threat_score}</td>
      `;
      suspiciousTableBody.appendChild(row);
    });
  })
  .catch((error) =>
    console.error("Erreur lors de la récupération des données:", error)
  );

fetch("http://127.0.0.1:5000/init_access")
  .then((response) => response.json())
  .then((data) => {

    if (data.initial_access && data.initial_access.ip) {
      globalIp = data.initial_access.ip;

      document.getElementById(
        "ip"
      ).textContent = `IP: ${data.initial_access.ip}`;
      document.getElementById(
        "mac"
      ).textContent = `MAC: ${data.initial_access.mac_address}`;
      document.getElementById(
        "machine"
      ).textContent = `Nom Machine: ${data.initial_access.nom_machine}`;
      document.getElementById(
        "user"
      ).textContent = `Utilisateur: ${data.initial_access.nom_utilisateur}`;
      document.getElementById("flag").textContent = `Flag: ${data.message}`;

      // Exécuter le deuxième fetch une fois l'IP obtenue
      return fetch(`http://127.0.0.1:5000/private_access/${globalIp}`);
    } else {
      throw new Error("Aucune IP trouvée dans la réponse");
    }
  })
  .then((response) => response.json())
  .then((data) => {

    // Forcer 'tentatives_dacces_entre_ips_privees' à être un tableau
    const tentativesDacces = Array.isArray(
      data.tentatives_dacces_entre_ips_privees
    )
      ? data.tentatives_dacces_entre_ips_privees
      : Object.values(data.tentatives_dacces_entre_ips_privees || {});
    const tableBody = document.querySelector("#tentatives-table tbody");

    // Itérer sur le tableau de tentatives d'accès
    tentativesDacces.forEach((entry) => {
      console.log(entry.nb_tentatives);
      console.log(attackObject[0].brutforce);
      if(entry.ports.length >= 40 ){
        attackObject[1].analysePort = 1;
      }
      if(entry.nb_tentatives >= 100){
        attackObject[0].brutforce = 1;
      }
      console.log(attackObject[0].brutforce)
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${entry.src_ip}</td>
        <td>${entry.dst_ip}</td>
        <td>${entry.nb_tentatives}</td>
        <td>${entry.protocols}</td>
        <td>${entry.ports}</td>
      `;
      tableBody.appendChild(row);
    });

    // Récupérer les connexions publiques après avoir récupéré l'IP initiale
    return fetch(`http://127.0.0.1:5000/public_access/${globalIp}`);
  })
  .then((response) => response.json())
  .then((data) => {

    // Accéder aux données des tentatives d'accès publiques
    const publicTentatives = Object.entries(data).map(([ip, entry]) => ({
      src_ip: ip,
      nb_tentatives: entry.nb_tentatives,
      ports: entry.ports.join(", "), // Si plusieurs ports, les concaténer en une seule chaîne
    }));


    const publicTableBody = document.querySelector(
      "#public-tentatives-table"
    );

    // Itérer sur les tentatives d'accès publiques
    publicTentatives.forEach((entry) => {
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${globalIp}</td>
        <td>${entry.src_ip}</td>
        <td>${entry.nb_tentatives}</td>
        <td>${entry.ports}</td>
      `;
      publicTableBody.appendChild(row);
    });
    const attackTableBody = document.querySelector("#attack-table");
    attackObject.forEach((entry) => {
      console.log(entry)
      if (entry.analysePort == 1){
        row = document.createElement("tr");
        row.innerHTML = `<td>Analyse de ports</td>`;
        attackTableBody.appendChild(row)
      }
      else if (entry.brutforce == 1){
        row = document.createElement("tr");
        row.innerHTML = `<td>Bruteforce</td>`;
        attackTableBody.appendChild(row)
      }
});
  })
  .catch((error) =>
    console.error("Erreur lors de la récupération des données:", error)
  );

// Fonction pour étendre les lignes du tableau
document.addEventListener("DOMContentLoaded", () => {
  const expandableCells = document.querySelectorAll(".expandable");

  expandableCells.forEach((cell) => {
    // Si le contenu est trop long, on affiche le bouton
    if (cell.scrollWidth > cell.clientWidth) {
      const expandButton = document.createElement("button");
      expandButton.textContent = "Afficher plus";
      expandButton.onclick = () => {
        // Étendre la cellule en changeant la classe CSS
        cell.classList.toggle("expanded");
        expandButton.textContent = cell.classList.contains("expanded")
          ? "Afficher moins"
          : "Afficher plus";
      };
      cell.appendChild(expandButton);
    }
  });
});
var map = L.map('map').setView([0, 0], 2);
const certTableBody = document.querySelector(
      "#cert-table"
    )
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
}).addTo(map);
    fetch("http://127.0.0.1:5000/map")
      .then((response) => response.json())
      .then((data) => {
        autoCert = false
        data.data.forEach((entry) => {
          
          if (entry.country != "inconnu"){
            L.marker([entry.latitude, entry.longitude]).addTo(map)
              .bindPopup(entry.country)
              .openPopup();
          }
          else {
            autoCert = true
            entry.ip.forEach((ip) => {
            const row = document.createElement("tr");
            row.innerHTML = `<td>${ip}</td>`;
            certTableBody.appendChild(row);});
          }
        });
        if (autoCert == false){
            row = document.createElement("tr");
            row.innerHTML = `<td>Aucun certificat auto-signé</td>`;
            certTableBody.appendChild(row)
          }
        ;})

