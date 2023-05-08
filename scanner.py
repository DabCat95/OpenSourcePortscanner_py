from scapy.all import Ether, IP, TCP, sr1

import getmac
import ipaddress
import socket

#Get Local IP Address
local_ip = socket.gethostbyname(socket.gethostname())
print(f"Your local IP Address is {local_ip}")

#Prompt user for IP Range
ip_range_str = input("Enter IP range to scan (in CIDR notation, e.g. '192.168.1.0/24)")
ip_range = ipaddress.IPv4Network(ip_range_str)

#Create IP Network Object
network = ipaddress.ip_network('192.168.1.0/24')

#Check if IP Address belongs to Network
ip = ipaddress.ip_address('192.168.1.10')
if ip in network:
    print(f"{ip} is in the network {network}")
else:
    print(f"{ip} is not in the network {network}")

#Iterate over IP addresses in the network
for ip in network.hosts():
    print(ip)

#Identify user MAC Address
mac_address = getmac.get_mac_address()
print(f"Your machine is currently connected to the following Mac Address: {mac_address}")

#Prompt user for MAC Address
mac = input("Enter Mac Address to use. (e.g. 00:11:22:33:44:55): ")

#Create Ethernet layer with Mac address
ether = Ether(dst=mac)

#Define Port range and create xrange object
port_range = (1, 1024)
ports = range(port_range[0], port_range[1]+1)
tcp =  TCP(dport=ports, flags="S")

#Create packets and send
for ip in ip_range:
    packet = ether/IP(dst=str(ip))/tcp
    response = sr1(packet, timeout=1, verbose=0)

    #Analyze Response
    if response and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            print(f"Port {response.dport} is open")
        elif response.getlayer(TCP).flags == 0x14:
            print(f"Port {response.dport} is closed")
