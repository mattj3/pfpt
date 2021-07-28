import nmap

# ask user for ip address they want to scan 

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool.")
print("^----------------------------------------------^")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
# Add in try catch for things other than ip addresses

# What is this doing? 
type(ip_addr)

# select what type of scan they want to conduct 
response = input("""  \nPlease enter the type of scan you want to run
                        1) SYN ACK Scan
                        2) UDP Scan
                        3) Comprehensive Scan  \n""")

print("You have selected option: ", response)

if response == '1':
    print("Nmap Version: ", scanner.nmap_version())
    # Ip address and range of ports
    # -v verbose 
    ## -sS SYN ACK Scan
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    # Check to see if IP address is online
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    # Return all open ports (in specified range)
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif response == '2':  
    print("Nmap Version: ", scanner.nmap_version())
    # Ip address and range of ports
    # -v verbose 
    ## -sU UDP port scan
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    # Check to see if IP address is online
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    # Return all open ports (in specified range)
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif response == '3':  
    print("Nmap Version: ", scanner.nmap_version())
    # Ip address and range of ports
    # -v verbose 
    ## Comprehensive scan
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    # Check to see if IP address is online
    print("IP Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    # Return all open ports (in specified range)
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
else:
    print("You have provided a scan type that is not supported, please try again.")