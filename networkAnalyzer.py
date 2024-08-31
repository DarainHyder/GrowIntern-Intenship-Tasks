from scapy.all import sniff, IP, TCP, UDP

# Function to check for potential threats
def check_for_threats(packet):
    # Example threat detection based on port number (e.g., port 23 for Telnet)
    suspicious_ports = [23, 2323]
    
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.dport in suspicious_ports or tcp_layer.sport in suspicious_ports:
            print("Alert! Suspicious TCP traffic detected.")
    
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        if udp_layer.dport in suspicious_ports or udp_layer.sport in suspicious_ports:
            print("Alert! Suspicious UDP traffic detected.")

# Function to process each packet
def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"New Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        # Check for threats
        check_for_threats(packet)
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Port: {tcp_layer.sport} -> {tcp_layer.dport}")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Port: {udp_layer.sport} -> {udp_layer.dport}")

# Start sniffing the network with threat detection
print("Starting network traffic analyzer with threat detection...")
sniff(prn=process_packet, store=False)
