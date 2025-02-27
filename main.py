# Import Libraries
from init import init_colorama, init_interface
from utils import get_host_info, scan_ports
from utils import get_network_info, scan_network, scan_network_devices
from utils import GREEN, RESET, GRAY
import sys
import json
import os
import time

def main():
    init_colorama()
    init_interface()
    create_out_folder()
    continue_loop = True
    while continue_loop:
        loopPrincipal()
        print(f"{GREEN}\nDeseja realizar outro escaneamento?{RESET}")
        print("Digite 's' para sim ou 'n' para não.")
        while True:
            choice = input("\nDigite sua escolha: ")
            choice = choice.lower()
            if choice == "s":
                break
            else:
                if choice == "n":
                    continue_loop = False
                    break
                else:
                    print("Opção inválida. Tente novamente.")
    print("\nAté a próxima!")


def create_out_folder():
    """
    Create the output folder if it doesn't exist.
    """
    if not os.path.exists("out"):
        os.makedirs("out")

def loopPrincipal():
    """
    Main function
    """


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
        
        verbose = False
        if len(sys.argv) > 1:
            if sys.argv[1] == "-v":
                verbose = True
                print("Modo verbose ativado.")
            
        host, protocol, start_port, end_port = get_host_info()
        
        print(f"\nEscaneando host {host}...")
        print(f"Protocolo: {protocol}")
        print(f"Portas: {start_port} - {end_port}")
        
        scan_result = None
        if protocol == "tcp":    
            scan_result = scan_ports(verbose, host, start_port, end_port, udp_scan=False)
        else:
            scan_result = scan_ports(verbose, host, start_port, end_port, udp_scan=True)
            
        with open("ports.json", "r") as file:
            well_known_ports = json.load(file)
            
        if scan_result != None:
            if scan_result != {}:
                # Escreve um relatório
                try:
                    time_now = time.strftime('%Y-%m-%d_%H-%M-%S')
                    with open(f"./out/relatorio_analise_individual_{host}_{time_now}.txt", "w") as file:
                        file.write(f"Host: {host}\n")
                        file.write(f"Protocolo: {protocol}\n")
                        file.write(f"Portas:\n")
                        for port, status in scan_result.items():
                            service = well_known_ports.get(str(port), "Desconhecido")
                            file.write(f"Porta {port}: {status} -> {service}\n")
                            
                    print(f"\nRelatório completo de portas abertas e filtradas salvo em {GREEN}./out/relatorio_analise_individual_{host}_{time_now}.txt{RESET}")

                except Exception as e:
                    print(f"{GRAY}Erro ao salvar o relatório: {e}{RESET}")
            else:
                print(f"\n{GREEN}Nenhuma porta aberta ou filtrada foi encontrada.{RESET}")
        else:
            print(f"\n{GREEN}Nenhuma porta aberta ou filtrada foi encontrada.{RESET}")
        
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