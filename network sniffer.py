
Building a network sniffer in Python on Kali Linux involves several steps. The steps below outline the process of setting up the environment, writing the Python script, and running the network sniffer to capture and analyze network traffic.

from scapy.all import snifff
from scapy.layers.inet import IP, TCP, UDP
import logging

logging.basicConfig(filename='packets.log', level=logging.INFO)

def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        log_message = f"[IP] {ip_layer.src} -> {ip_layer.dst}"
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            log_message += f" [TCP] {tcp_layer.sport} -> {tcp_layer.dport}"
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            log_message += f" [UDP] {udp_layer.sport} -> {udp_layer.dport}"
        
        print(log_message)
        logging.info(log_message)

def main():
    print("Starting network sniffer...")
    sniff(prn=packet_handler, store=0)

if __name__ == "__main__":
    main()
