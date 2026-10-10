# Port Scanner - Nmap Simplifié

## Description
Ce projet est un scanner de ports léger inspiré de Nmap. Il permet de vérifier les ports ouverts d’une cible, de détecter les services associés, de générer un rapport JSON et de tester plusieurs méthodes de scan TCP.

---

## Fonctionnalités
- Scan TCP et UDP
- Support des plages et listes de ports : `20-80`, `22,80,443`, `443-444`
- Détection des services via `socket.getservbyport`
- Export des résultats au format JSON
- Détection OS estimée par TTL ICMP
- Méthodes de scan TCP : `connect`, `syn`, `ack`
- Multithreading pour accélérer le scan
- Affichage coloré dans le terminal

---

## Prérequis
Installez les dépendances du projet :

```bash
python3 -m pip install -r requirements.txt
```

Le fichier [requirements.txt](requirements.txt) contient :
- `scapy`
- `colorama`

---

## Utilisation

### Commande de base
```bash
python3 port_scanner.py <hote> -p <ports> -t <tcp|udp>
```

### Exemples
1. Scan TCP classique sur une plage de ports :
```bash
python3 port_scanner.py 192.168.1.1 -p 20-80 -t tcp
```

2. Scan TCP avec une liste de ports :
```bash
python3 port_scanner.py 192.168.1.1 -p "22,80,443" -t tcp
```

3. Scan UDP :
```bash
python3 port_scanner.py 192.168.1.1 -p 20-80 -t udp
```

4. Rapport JSON dans la console :
```bash
python3 port_scanner.py 192.168.1.1 -p "22,80,443" -t tcp --json
```

5. Rapport JSON sauvegardé dans un fichier :
```bash
python3 port_scanner.py 192.168.1.1 -p "22,80,443" -t tcp --json --output scan.json
```

6. Détection OS estimée :
```bash
python3 port_scanner.py 192.168.1.1 -p 80 -t tcp --os-detect
```

7. Scan SYN :
```bash
python3 port_scanner.py 192.168.1.1 -p 20-80 -t tcp --scan-method syn
```

8. Scan ACK :
```bash
python3 port_scanner.py 192.168.1.1 -p 20-80 -t tcp --scan-method ack
```

9. Aide :
```bash
python3 port_scanner.py -h
```

---

## Exemple de sortie
```text
Scanning des ports de 192.168.1.1 (20-80) sur le protocole TCP
[TCP] Port 80 ouvert, Service: http

Ports ouverts sur 192.168.1.1:
TCP 80: http
```

---

## Notes de sécurité
- Ce projet est conçu uniquement pour des tests éthiques et des environnements autorisés.
- N’utilisez pas cet outil sur des systèmes sans permission explicite.
- Les scans réseau peuvent être détectés et peuvent être illégaux hors de votre propre environnement.

---

## Développements futurs possibles
- Interface graphique plus conviviale
- Rapport CSV/HTML supplémentaire
- Détection OS plus précise
- Scan plus discret et filtré
- Analyse approfondie des services UDP