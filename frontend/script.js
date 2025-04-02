fetch("http://127.0.0.1:5000/init_access")
  .then((response) => response.json())
  .then((data) => {
    console.log(data);
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
  })
  .catch((error) =>
    console.error("Erreur lors de la récupération des données:", error)
  );
