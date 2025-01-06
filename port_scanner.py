import socket
import threading
import scapy.all as scapy
from colorama import Fore, init
import argparse

# Initialisation de Colorama pour les couleurs dans le terminal
init(autoreset=True)

# Fonction pour scanner un port TCP
def scan_tcp(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            return True  # Port ouvert
        else:
            return False  # Port fermé
    except socket.error:
        return False  # Erreur de connexion
    finally:
        sock.close()

# Fonction pour scanner un port UDP
def scan_udp(host, port):
    try:
        pkt = scapy.UDP(dport=port) / "Test"
        response = scapy.sr1(pkt, timeout=1, verbose=False)
        if response:
            return True  # Port UDP ouvert
        else:
            return False  # Pas de réponse, donc fermé
    except Exception as e:
        return False  # En cas d'erreur

# Fonction pour détecter les services
def detect_service(port, protocol):
    try:
        if protocol == "tcp":
            service = socket.getservbyport(port, protocol)
        else:
            service = "UDP Service"  # À implémenter pour détecter les services UDP
        return service
    except:
        return "Unknown Service"

# Fonction de scan de port avec multithreading
def scan_ports(host, ports, protocol):
    open_ports = []
    threads = []

    for port in ports:
        thread = threading.Thread(target=scan_port, args=(host, port, protocol, open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports

# Fonction pour scanner chaque port et afficher les résultats
def scan_port(host, port, protocol, open_ports):
    if protocol == "tcp":
        if scan_tcp(host, port):
            service = detect_service(port, protocol)
            open_ports.append((port, service, "TCP"))
            print(f"{Fore.GREEN}[TCP] Port {port} ouvert, Service: {service}")
        else:
            print(f"{Fore.RED}[TCP] Port {port} fermé")
    elif protocol == "udp":
        if scan_udp(host, port):
            service = detect_service(port, protocol)
            open_ports.append((port, service, "UDP"))
            print(f"{Fore.GREEN}[UDP] Port {port} ouvert, Service: {service}")
        else:
            print(f"{Fore.RED}[UDP] Port {port} fermé")

# Fonction principale
def main():
    parser = argparse.ArgumentParser(description="Scanner de Ports Nmap Simplifié")
    parser.add_argument("host", help="Hôte à scanner (ex: 192.168.1.1)")
    parser.add_argument("-p", "--ports", help="Plage de ports à scanner (ex: 20-80)", default="20-80")
    parser.add_argument("-t", "--type", help="Type de protocole (tcp ou udp)", choices=["tcp", "udp"], default="tcp")

    args = parser.parse_args()

    # Récupérer la plage de ports
    port_range = args.ports.split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])

    # Lancer le scan de ports
    print(f"Scanning des ports de {args.host} ({start_port}-{end_port}) sur le protocole {args.type.upper()}")
    open_ports = scan_ports(args.host, range(start_port, end_port + 1), args.type)

    # Résultats finaux
    if open_ports:
        print(f"\nPorts ouverts sur {args.host}:")
        for port, service, protocol in open_ports:
            print(f"{protocol} {port}: {service}")
    else:
        print(f"Aucun port ouvert trouvé sur {args.host}")

if __name__ == "__main__":
    main()