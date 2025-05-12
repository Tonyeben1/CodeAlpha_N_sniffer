import socket
import struct

from scapy.all import sniff, get_if_list, Ether, IP, TCP

def process_packet(packet):
    if packet.haslayer(Ether):
        eth = packet[Ether]
        print("=== Ethernet Frame ===")
        print(f"Source MAC: {eth.src}")
        print(f"Destination MAC: {eth.dst}")
        print(f"EtherType: {hex(eth.type)}")

    if packet.haslayer(IP):
        ip = packet[IP]
        print("--- IP Packet ---")
        print(f"Source IP: {ip.src}")
        print(f"Destination IP: {ip.dst}")
        print(f"TTL: {ip.ttl}")
        print(f"Protocol: {ip.proto}")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print("+++ TCP Segment +++")
        print(f"Source Port: {tcp.sport}")
        print(f"Destination Port: {tcp.dport}")
        print(f"Flags: {tcp.flags}")
    
    print("----------------------\n")

def choose_interface():
    interfaces = get_if_list()
    print("Available Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    
    index = int(input("Select the interface number to sniff on: "))
    return interfaces[index]

# Ask user to select interface
iface = choose_interface()

# Start sniffing on the selected interface
sniff(iface=iface, prn=process_packet, store=0)



def sniff_packets():
    # Create a raw socket on Windows (requires admin)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Get the local machine name and bind
    host = socket.gethostbyname(socket.gethostname())
    s.bind((host, 0))

    # Include IP headers
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode (only works on Windows)
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            packet = s.recvfrom(65565)[0]

            # Extract IP header (first 20 bytes)
            ip_header = packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            if protocol != 6:  # Only TCP
                continue

            # Extract TCP header
            tcp_header = packet[iph_length:iph_length+20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = (doff_reserved >> 4) * 4

            # Extract data
            h_size = iph_length + tcph_length
            data = packet[h_size:]

            # Print info
            print('--- Packet Captured ---')
            print('IP Header')
            print('Version:', version)
            print('IHL:', ihl)
            print('TTL:', ttl)
            print('Protocol:', protocol)
            print('Source IP:', s_addr)
            print('Destination IP:', d_addr)
            print('TCP Header')
            print('Source Port:', source_port)
            print('Destination Port:', dest_port)
            print('Sequence Number:', sequence)
            print('Acknowledgement:', acknowledgement)
            print('TCP Header Length:', tcph_length)
            print('Data:', data)
            print('------------------------\n')

    except KeyboardInterrupt:
        # Disable promiscuous mode when exiting
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("Stopped sniffing.")






