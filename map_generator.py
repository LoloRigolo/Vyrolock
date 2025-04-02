import folium

# Position [latitude, longitude] sur laquelle est centrée la carte
location = [47, 1]

# Niveau de zoom initial : 
# 3-4 pour un continent, 5-6 pour un pays, 11-12 pour une ville
zoom = 6

# Style de la carte
tiles = 'cartodb positron'

# Créer la carte
carte = folium.Map(location=location, zoom_start=zoom, tiles=tiles)

# Sauvegarder la carte dans un fichier HTML
carte.save("carte_interactive.html")

# Ajouter le JavaScript et CSS pour modifier dynamiquement le style
with open("carte_interactive.html", "r") as file:
    html_content = file.read()

# Ajouter un script JavaScript pour cibler l'élément de la carte et modifier son style
js_script = """
<script>
document.addEventListener('DOMContentLoaded', function() {
    // Cibler l'élément dont l'id commence par 'map_'
    var mapElement = document.querySelector('[id^="map_"]');
    
    if (mapElement) {
        // Modifier le style CSS de la carte
        mapElement.style.width = '50%'; // 80% de la largeur de la page
        mapElement.style.height = '70vh'; // 70% de la hauteur de la fenêtre
        mapElement.style.margin = '0 auto'; // Centrer horizontalement
        mapElement.style.border = '2px solid #000'; // Ajouter une bordure noire autour de la carte
    }
});
</script>
"""

# Ajouter le script JavaScript avant la fin de la balise </body>
html_content = html_content.replace("</body>", js_script + "</body>")

# Sauvegarder le fichier HTML modifié en écrasant l'original
with open("carte_interactive.html", "w") as file:
    file.write(html_content)



