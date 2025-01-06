# Port Scanner - Nmap Simplifié

## Description
Ce projet est un **scanner de ports simplifié** inspiré de Nmap. Il permet d'analyser les ports ouverts sur une machine cible (hôte) en utilisant les protocoles **TCP** et **UDP**. Le programme utilise des **threads** pour accélérer le processus de scan et peut également détecter les **services** associés aux ports ouverts.

### Fonctionnalités principales :
- **Scan TCP et UDP** : Vérifie si un port est ouvert ou fermé.
- **Détection de services** : Identifie les services associés aux ports TCP ouverts.
- **Multithreading** : Exécution rapide grâce au traitement parallèle.
- **Affichage coloré** : Utilise la bibliothèque **Colorama** pour des messages colorés dans le terminal.

---

## Prérequis
### Bibliothèques nécessaires :
1. **Python 3.11 ou supérieur**
2. Modules Python :
   - **socket** (inclus par défaut)
   - **threading** (inclus par défaut)
   - **argparse** (inclus par défaut)
   - **scapy** :
     ```bash
     pip install scapy
     ```
   - **colorama** :
     ```bash
     pip install colorama
     ```

---

## Instructions d'exécution

### Commande de base :
```bash
python3.11 port_scanner.py <hôte> -p <ports> -t <protocole>
```

### Exemples :
1. Scanner les ports **22, 80 et 443** sur le protocole **TCP** :
```bash
python3.11 port_scanner.py 192.168.1.1 -p 22-443 -t tcp
```

2. Scanner les ports de **20 à 80** sur le protocole **UDP** :
```bash
python3.11 port_scanner.py 192.168.1.1 -p 20-80 -t udp
```

3. Obtenir de l'aide :
```bash
python3.11 port_scanner.py -h
```

---

## Améliorations possibles
Voici quelques améliorations suggérées pour enrichir le projet :

1. **Support des listes de ports spécifiques** :
   - Actuellement, seules les plages de ports sont supportées. Ajouter la gestion des listes de ports (par ex. `22,80,443`).

2. **Détection de services UDP** :
   - Implémenter un mécanisme similaire à TCP pour identifier les services UDP.

3. **Rapport au format CSV ou JSON** :
   - Exporter les résultats des scans dans un fichier pour faciliter leur analyse ultérieure.

4. **Détection des systèmes d'exploitation** :
   - Ajouter des fonctionnalités d'analyse pour estimer le système d'exploitation de l'hôte.

5. **Scan avancé** :
   - Implémenter des techniques avancées comme les scans SYN ou ACK pour une analyse plus discrète.

6. **Interface graphique** :
   - Créer une application avec une interface utilisateur pour une utilisation plus conviviale.

---

## Notes importantes
- Ce scanner est conçu pour des **tests éthiques** uniquement.
- Utilisez-le sur vos propres réseaux ou avec une **autorisation préalable**.
- Tout usage abusif peut être **illégal** et entraîner des poursuites judiciaires.