import socket
import threading
import argparse
import json

try:
    import scapy.all as scapy
except ModuleNotFoundError:
    scapy = None

from colorama import Fore, init


def parse_ports(port_spec):
    """Convert a port list like '20-22,80,443-444' into a sorted unique list."""
    if isinstance(port_spec, (list, tuple, range)):
        ports = [int(port) for port in port_spec]
    else:
        ports = []
        for part in str(port_spec).split(","):
            item = part.strip()
            if not item:
                continue
            if "-" in item:
                start, end = (p.strip() for p in item.split("-", 1))
                start_port = int(start)
                end_port = int(end)
                if start_port > end_port:
                    start_port, end_port = end_port, start_port
                ports.extend(range(start_port, end_port + 1))
            else:
                ports.append(int(item))

    unique_ports = []
    seen = set()
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"Le port {port} n'est pas valide. Il doit être compris entre 1 et 65535.")
        if port not in seen:
            unique_ports.append(port)
            seen.add(port)
    return sorted(unique_ports)


def build_report(open_ports):
    """Return the scan results as a JSON string."""
    report = [{"port": port, "service": service, "protocol": protocol} for port, service, protocol in open_ports]
    return json.dumps(report, indent=2)

# Initialisation de Colorama pour les couleurs dans le terminal
init(autoreset=True)

# Fonction pour scanner un port TCP
def scan_tcp(host, port, method="connect"):
    if method == "syn":
        if scapy is None:
            raise RuntimeError("Le module 'scapy' est requis pour un scan SYN.")
        try:
            pkt = scapy.IP(dst=host) / scapy.TCP(dport=port, flags="S")
            response = scapy.sr1(pkt, timeout=1, verbose=False)
            if response and response.haslayer(scapy.TCP):
                flags = response.getlayer(scapy.TCP).flags
                return "S" in str(flags) and "A" in str(flags)
            return False
        except Exception:
            return False

    if method == "ack":
        if scapy is None:
            raise RuntimeError("Le module 'scapy' est requis pour un scan ACK.")
        try:
            pkt = scapy.IP(dst=host) / scapy.TCP(dport=port, flags="A")
            response = scapy.sr1(pkt, timeout=1, verbose=False)
            if response and response.haslayer(scapy.TCP):
                flags = str(response.getlayer(scapy.TCP).flags)
                return "R" in flags or "A" in flags
            return False
        except Exception:
            return False

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
    if scapy is None:
        print(f"{Fore.YELLOW}Le module 'scapy' n'est pas installé. Installez-le avec: pip install scapy")
        return False

    try:
        pkt = scapy.UDP(dport=port) / "Test"
        response = scapy.sr1(pkt, timeout=1, verbose=False)
        if response:
            return True  # Port UDP ouvert
        else:
            return False  # Pas de réponse, donc fermé
    except Exception:
        return False  # En cas d'erreur

# Fonction pour détecter les services
def detect_service(port, protocol):
    protocol = protocol.lower()
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "Unknown Service"


def detect_os(host):
    """Estimation simple du système d'exploitation via le TTL d'un paquet ICMP."""
    if scapy is None:
        return "Unknown (install scapy)"

    try:
        packet = scapy.IP(dst=host) / scapy.ICMP()
        response = scapy.sr1(packet, timeout=2, verbose=False)
        if response and response.haslayer(scapy.IP):
            ttl = int(response.ttl)
            if ttl <= 64:
                return "Linux / Unix-like"
            if ttl <= 128:
                return "Windows"
            if ttl <= 255:
                return "Cisco / Unix-like"
        return "Unknown"
    except Exception:
        return "Unknown"

# Fonction de scan de port avec multithreading
def scan_ports(host, ports, protocol, method="connect"):
    open_ports = []
    threads = []
    lock = threading.Lock()

    for port in ports:
        thread = threading.Thread(target=scan_port, args=(host, port, protocol, open_ports, lock, method))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return open_ports

# Fonction pour scanner chaque port et afficher les résultats
def scan_port(host, port, protocol, open_ports, lock, method="connect"):
    if protocol == "tcp":
        if scan_tcp(host, port, method):
            service = detect_service(port, protocol)
            with lock:
                open_ports.append((port, service, "TCP"))
                print(f"{Fore.GREEN}[TCP] Port {port} ouvert, Service: {service}")
        else:
            with lock:
                print(f"{Fore.RED}[TCP] Port {port} fermé")
    elif protocol == "udp":
        if scan_udp(host, port):
            service = detect_service(port, protocol)
            with lock:
                open_ports.append((port, service, "UDP"))
                print(f"{Fore.GREEN}[UDP] Port {port} ouvert, Service: {service}")
        else:
            with lock:
                print(f"{Fore.RED}[UDP] Port {port} fermé")

# Fonction principale
def main():
    parser = argparse.ArgumentParser(description="Scanner de Ports Nmap Simplifié")
    parser.add_argument("host", help="Hôte à scanner (ex: 192.168.1.1)")
    parser.add_argument("-p", "--ports", help="Ports à scanner (ex: 20-80 ou 22,80,443-444)", default="20-80")
    parser.add_argument("-t", "--type", help="Type de protocole (tcp ou udp)", choices=["tcp", "udp"], default="tcp")
    parser.add_argument("--scan-method", choices=["connect", "syn", "ack"], default="connect", help="Méthode de scan TCP (connect, syn, ack)")
    parser.add_argument("--os-detect", action="store_true", help="Estime le système d'exploitation de la cible")
    parser.add_argument("--json", action="store_true", help="Affiche le rapport au format JSON")
    parser.add_argument("--output", help="Enregistre le rapport JSON dans un fichier")

    args = parser.parse_args()

    if args.type == "udp" and scapy is None:
        print(f"{Fore.RED}Erreur: le module 'scapy' est obligatoire pour le scan UDP.")
        print(f"{Fore.YELLOW}Installer la dépendance avec: pip install scapy")
        raise SystemExit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    if not ports:
        parser.error("Aucun port valide n'a été fourni. Utilisez une plage ou une liste comme 20-80 ou 22,80,443-444.")

    start_port = min(ports)
    end_port = max(ports)

    print(f"Scanning des ports de {args.host} ({start_port}-{end_port}) sur le protocole {args.type.upper()}")
    if args.os_detect and args.type == "tcp":
        print(f"{Fore.CYAN}Système estimé: {detect_os(args.host)}")

    open_ports = scan_ports(args.host, ports, args.type, args.scan_method if args.type == "tcp" else "connect")

    if args.json:
        report = build_report(open_ports)
        print(report)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report)
                f.write("\n")
        return

    if open_ports:
        print(f"\nPorts ouverts sur {args.host}:")
        for port, service, protocol in open_ports:
            print(f"{protocol} {port}: {service}")
    else:
        print(f"Aucun port ouvert trouvé sur {args.host}")

if __name__ == "__main__":
    main()