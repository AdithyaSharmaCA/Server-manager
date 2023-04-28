import psutil
import os
from scapy.all import*
import time
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP 
from scapy.layers.inet import IP
# Get CPU utilization
import socket

def resource_utilization():
    # Get memory utilization
    cpu_usage = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    mem_total = mem.total / (1024 ** 2) # Convert bytes to MB
    mem_used = mem.used / (1024 ** 2) # Convert bytes to MB
    mem_usage = (mem.used / mem.total) * 100
    print(f"CPU usage: {cpu_usage}%")
    print(f"Memory usage: {mem_used:.2f} MB / {mem_total:.2f} MB ({mem_usage:.2f}%)")
    return {
        "cpu_usage": cpu_usage,
        "mem_total": mem_total,
        "mem_used": mem_used,
        "mem_usage": mem_usage
    }
resource_utilization()

def get_bandwidth(interval=1):
    bytes_sent = psutil.net_io_counters().bytes_sent
    bytes_recv = psutil.net_io_counters().bytes_recv
    time.sleep(interval)
    bytes_sent_new = psutil.net_io_counters().bytes_sent
    bytes_recv_new = psutil.net_io_counters().bytes_recv
    bytes_sent_diff = bytes_sent_new - bytes_sent
    bytes_recv_diff = bytes_recv_new - bytes_recv
    return (bytes_sent_diff / interval, bytes_recv_diff / interval)

sent, received = get_bandwidth(interval=5)
print(f"Bytes sent per second: {sent}")
print(f"Bytes received per second: {received}")

def sniff_http_get_requests(server_ip):
    # Define a filter to capture only HTTP GET requests to the specified server
    filter_str = "tcp dst port 80 and ip dst {}".format(server_ip)

    # Define a function to print the details of each HTTP GET request
    def print_request(packet):
        # Check if the packet is an HTTP GET request
        if packet.haslayer(Raw) and "GET /" in str(packet[Raw]):
            print("HTTP GET request received:")
            print("Source IP: {}".format(packet[IP].src))
            print("Destination IP: {}".format(packet[IP].dst))
            print("Packet length: {}".format(len(packet)))
            print("Request URI: {}".format(str(packet[Raw]).split(" ")[1]))

    # Use Scapy's sniff() function to capture packets on the network
    sniff(filter=filter_str, prn=print_request)

WEB_SERVER_IP = " " # WE CAN JUST ENTER IN THE REQUIRED WEB SERVER IP THAT WE WANT TO MONITOR

#sniff_http_get_requests("127.0.0.1")
def is_port_open(ip_address, port):
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    
    # Try to connect to the given IP address and port
    result = sock.connect_ex((ip_address, port))
    
    # Check the result
    if result == 0:
        # Port is open
        return True
    else:
        # Port is closed or unreachable
        return False
print(is_port_open("localhost",5001))


TCP_list = []
# Sniff packets from network interface
def packet_handler(packet):
    if packet.haslayer(TCP):
        tcp_packet = packet[TCP]
        if TCP in tcp_packet and tcp_packet[TCP].dport == 5001:  # Filter packets for port 80 (HTTP)
            print("Sniffed TCP packet: ", tcp_packet.summary())
            tcp_packet.show()   
            TCP_list.append(tcp_packet)
# Sniff packets with the custom packet handler
sniff(filter = "tcp",prn=packet_handler)
print(len(TCP_list))


handshake_counter=0
# Define the callback function to process sniffed packets
def process_packet(packet):
    global handshake_counter
    # Check for SYN packet
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        # Check for SYN-ACK packet
        syn_ack_packet = sniff(filter=f"tcp and host {packet[IP].dst} and port {packet[TCP].dport}", count=1)
        if syn_ack_packet and syn_ack_packet[0][TCP].flags == 'SA':
            # Check for ACK packet
            ack_packet = sniff(filter=f"tcp and host {packet[IP].src} and port {packet[TCP].sport}", count=1)
            if ack_packet and ack_packet[0][TCP].flags == 'A':
                # Increment handshake counter
                handshake_counter += 1
                # Print current number of handshakes
                print(f"Number of handshakes: {handshake_counter}")
    print(packet.summary())
    print("the number of 3 way handshakes that happened in the last 100 entries are: ",handshake_counter)
    # Start sniffing packets on the network interface
sniff(filter="tcp", prn=process_packet,count = 100)
