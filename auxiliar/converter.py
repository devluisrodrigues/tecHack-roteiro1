def main():
    # open a csv file:
    lines = []
    with open("ports.csv", "r") as file:
        # read the file:
        data = file.read().strip().replace("\"", "")
        
        lines = data.split("\n")
        lines = lines[1:]
        
    with open("ports.json", "w") as file:
        file.write("{\n")
        for line in lines:
            palavras = line.split(",")
            print(line.split(","))
            protocolo = palavras[0]
            port = palavras[1]
            
            service = ""
            for palavra in palavras[2:]:
                service += palavra
    
            if protocolo == "TCP":
                file.write(f"    \"{port}\": \"{service}\",\n")
        file.write("}")
        

if __name__ == "__main__":
    main()