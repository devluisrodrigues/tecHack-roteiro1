# Import Libraries
from init import init_colorama, init_interface
from utils import get_host_info, scan_ports
from utils import get_network_info, scan_network, scan_network_devices
from utils import GREEN, RESET, GRAY

def main():
    """
    Main function
    """
    
    init_colorama()
    init_interface()

    print("Será escaneado um host ou uma rede?")
    print("Para escanear um host digite 'host', 'h', ou ''.")
    print("Para escanear uma rede digite 'network' ou 'n'.")
    while True:
        is_host = input("\nDigite sua escolha: ")
        is_host = is_host.lower()
        if is_host == "host" or is_host == "h" or is_host == "":
            is_host = 1
            break
        else:
            if is_host == "network" or is_host == "n":
                is_host = 0
                break
            else:
                print("Opção inválida. Tente novamente.")
    
    # Scan a host:
    if is_host:
        host, start_port, end_port = get_host_info()
        
        print(f"Escaneando host {host}...")
        
        scan_ports(0, host, start_port, end_port)
        
    # Scan a network: 
    else:
        network = get_network_info()
        devices = scan_network(network)
        print(f"\n{GREEN}Dispositivos encontrados:{RESET}\n")
        for device in devices:
            print(f"{GREEN}{device}{RESET}")
        
        scan_network_devices(devices)

if __name__ == "__main__":
    main()

# Referências:
# Port Scanning:
# https://www.youtube.com/watch?v=t9EX2RAUoTU
# https://www.techtarget.com/searchsecurity/tutorial/How-to-build-a-Python-port-scanner
# https://thepythoncode.com/article/make-port-scanner-python
# https://docs.python.org/3/library/socket.html

# Network scanning:
# https://github.com/HelsNetwork/Simple-Network-Scanner

# Banner Grabbing:
# https://github.com/Beek-Kefyalew/Python-Banner-Grabber/blob/master/bannerGrab.py
# https://johanneskinzig.de/index.php/it-security/12-port-scanning-and-banner-grabbing-with-python