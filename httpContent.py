from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import argparse


# Open the pcap file
parser = argparse.ArgumentParser(description="Displays user agents")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()


packets = rdpcap(args.file)

# Define a function to print the contents of HTTP packets
def print_http_packets(packets):
    for packet in packets:
        if HTTPRequest in packet and packet.haslayer(Raw):
            print(packet[Raw].load.decode())
        if HTTPResponse in packet and packet.haslayer(Raw):
            print(packet[Raw].load.decode())

# Call the function
print_http_packets(packets)
