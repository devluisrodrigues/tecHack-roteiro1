import socket
import regex as re
import json
import os

GREEN = '\033[92m'
RESET = '\033[0m'
GRAY = '\033[90m'
RED = '\033[91m'
YELLOW = '\033[93m'

def get_host_info():
    """
    Get host IP and port range to scan
    """
    print("Digite o endereço IP do host a ser escaneado:")
    
    # Get host IP
    host = ""
    while True:
        host = input("Host: ")
        if not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
            print("Endereço IP inválido. Tente novamente.")
        else:
            break
        
    # User decides whether to set a range of ports or scan all ports
    is_range = 0
    while True: # User decides whether to scan all ports or a range of ports
        is_range = input("Deseja escanear uma faixa de portas? Use 's' ou '1' para sim e 'n' ou '0' para não: ")
        is_range = is_range.lower()
        if is_range == "s" or is_range == "1":
            is_range = 1
            break
        else:
            if is_range == "n" or is_range == "0":
                is_range = 0
                break
            else:
                print("Opção inválida. Tente novamente.")
                
    # If user decides to scan all ports, return host and ports 1 to 1000
    if not is_range:
        return host, 1, 1000
    
    # If user decides to scan a range of ports, ask for the range
    else:
        print("Digite a faixa de portas a ser escaneada:")
        start_port = 0
        end_port = 0
        
        # Get start port
        while True:
            start_port = input("Porta inicial: ")
            if not start_port.isdigit():
                print("Porta inválida. Tente novamente.")
            else:
                start_port = int(start_port)
                if start_port < 1 or start_port > 65535:
                    print("Porta inválida. Tente novamente.")
                else:
                    break
                
        # Get end port
        while True:
            end_port = input("Porta final: ")
            if not end_port.isdigit():
                print("Porta inválida. Tente novamente.")
            else:
                end_port = int(end_port)
                if end_port < 1 or end_port > 65535:
                    print("Porta inválida. Tente novamente.")
                else:
                    break
        return host, start_port, end_port
                

def is_port_open(host, port):
    """
    Check if a port is open
    """
    skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Socket para conexão TCP e IPv4
    skt.settimeout(1)
      
    try:
        # print(f"Tentando conectar a {host} na porta {port}...")
        result = skt.connect_ex((host, port))
        if result == 0:
            return "open"  # Conexão bem-sucedida, porta aberta
        elif result == 111 or result == 10061:  # Connection refused (Linux e Windows)
            return "closed"
        else:
            return "filtered" 
    except socket.timeout:
        return "filtered"  # Sem resposta dentro do tempo limite
    except Exception as e:
        return f"error: {e}"
    finally:
        skt.close()

def scan_ports(verbose, host, start_port, end_port):
    """
    Scan a range of ports
    """
    
    # Le o json como dicionário
    with open("ports.json", "r") as file:
        well_known_ports = json.load(file)
    
    results = {}
    is_any_open = False
    is_any_filtered = False
    
    # Banner Grabbing:
    machine_os = ""
    banner_ports = [21, 22, 25, 80, 110, 143]
    
    for port in range(start_port, end_port + 1):
        result = is_port_open(host, port)
        results[port] = result
        if result == "open":
            is_any_open = True
            if port in banner_ports and machine_os == "":
                banner = grab_banner(host, port)
                print(f"\n{YELLOW}Banner encontrado na porta {port}:\n{RESET}{banner}")
                machine_os = identify_os(banner)
                if machine_os != "":
                    print(f"{GREEN}Sistema operacional identificado: {machine_os}{RESET}")
            
    if not is_any_open and not is_any_filtered:
        print(f"\n{RED}Nenhuma porta aberta encontrada.{RESET}\n")
        return {}
        
    else:
        print(f"\n{GREEN}Portas abertas encontradas:\n{RESET}")
        for port, result in results.items():
            if result == "open":
                service = well_known_ports.get(str(port), "Serviço desconhecido") # Relaciona porta ao Well-Known Port
                print(f"{GREEN}Porta {port}: {result} -> {service}{RESET}")
            elif result == "filtered":
                service = well_known_ports.get(str(port), "Serviço desconhecido") # Relaciona porta ao Well-Known Port
                print(f"{YELLOW}Porta {port}: {result} -> {service}{RESET}")
            else:
                if verbose:
                    print(f"{RED}Porta {port}: {result}{RESET}")
                    
        if not verbose:
            num_closed_ports = len([result for result in results.values() if result == "closed"])
            print(f"{RED}Outras {num_closed_ports} portas fechadas{RESET}")
                
    if not verbose:
        results = {port: result for port, result in results.items() if result != "closed"}
        
    return results

# Banner Grabbing:
def grab_banner(host, port):
    protocol_messages = {
        21: b'USER anonymous\r\n',  # FTP
        22: None,  # SSH (só conectar)
        25: b'EHLO test.com\r\n',  # SMTP
        80: b'HEAD / HTTP/1.1\r\nHost: site.com\r\n\r\n',  # HTTP
        110: b'USER test\r\n',  # POP3
        143: b'LOGIN test pass\r\n',  # IMAP
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2) 
        sock.connect((host, port))  
        if protocol_messages[port]:
            sock.send(protocol_messages[port])
        else:
            sock.send(b'HEAD / HTTP/1.1\r\n\r\n')  
        banner = sock.recv(1024) 
        sock.close()
        return banner.decode().strip() 
    except Exception as e:
        return f"Erro: {e}"
    
def identify_os(banner):
    banner = banner.lower()
    if "ubuntu" in banner:
        return "Linux (Ubuntu)"
    elif "debian" in banner:
        return "Linux (Debian)"
    elif "microsoft" in banner or "windows" in banner:
        return "Windows"
    elif "freebsd" in banner:
        return "FreeBSD"
    elif "centos" in banner:
        return "Linux (CentOS)"
    return ""


# Network scanning:
from scapy.all import ARP, Ether, srp

def get_network_info():
    """
    Get network info
    """
    print("Digite o endereço da rede a ser escaneada:")
    print("Siga o formato 'xxx.xxx.xxx.xxx/xx'.")
    network = ""
    while True:
        network = input("\nRede: ")
        if not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}", network):
            print("Endereço de rede inválido. Tente novamente.")
        else:
            break
    return network

def scan_network(network):
    """
    Descobre dispositivos ativos na rede.
    """
    arp_request = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def scan_network_devices(devices):
    """
    Scan the ports of the devices found
    """

    print("\nDeseja escanear as portas dos dispositivos encontrados?")
    while True:
        enable_scan_ports = input("Digite 's' ou '1' para sim e 'n' ou '0' para não: ")
        enable_scan_ports = enable_scan_ports.lower()
        if enable_scan_ports == "s" or enable_scan_ports == "1":
            enable_scan_ports = 1
            break
        else:
            if enable_scan_ports == "n" or enable_scan_ports == "0":
                enable_scan_ports = 0
                break
            else:
                print("Opção inválida. Tente novamente.")
                
    if enable_scan_ports:
        for device in devices:
            host = str(device['ip'])
            
            print(f"\n{GREEN}Escaneando dispositivo {host}{RESET}")
            results = scan_ports(0,host,1,1000)
            
            with open("ports.json", "r") as file:
                well_known_ports = json.load(file)
            
            # Cria o arquivo relatorio
            if os.path.exists("./out"):
                pass
            else:
                os.mkdir("./out")
            
            # Escreve um relatorio para cada dispositivo
            with open(f"./out/relatorio_{host}.txt", "w") as file:
                for port, result in results.items():
                    service = well_known_ports.get(str(port), "Serviço desconhecido")
                    file.write(f"Porta {port}: {result} -> {service}\n")
                    
            print(f"\n{GREEN}Relatório salvo em ./out/relatorio_{host}.txt{RESET}")