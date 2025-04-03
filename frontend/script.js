let globalIp = ""; // variable globale qui stocke l'IP

fetch("http://127.0.0.1:5000/init_access")
  .then((response) => response.json())
  .then((data) => {
    console.log(data);

    if (data.initial_access && data.initial_access.ip) {
      globalIp = data.initial_access.ip;
    
    document.getElementById("ip").textContent = `IP: ${data.initial_access.ip}`;
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
    console.log("Données reçues de /private_access :", data);

    // Accéder à la clé 'tentatives_dacces_entre_ips_privees'
    const tentativesDacces = data.tentatives_dacces_entre_ips_privees || [];

  // Insérer les données dans le tableau
    const tableBody = document.querySelector("#tentatives-table tbody");

    // Si 'tentativesDacces' est un tableau, on itère dessus pour insérer chaque entrée
    if (Array.isArray(tentativesDacces)) {
      tentativesDacces.forEach(entry => {
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
    } else {
      console.error("Les données reçues ne sont pas sous forme de tableau :", tentativesDacces);
    }
  })
  .catch((error) =>
    console.error("Erreur lors de la récupération des données:", error)
  );
  
  


