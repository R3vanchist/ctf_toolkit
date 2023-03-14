from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import argparse


# Open the pcap file
parser = argparse.ArgumentParser(description="Displays user agents")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()


packets = rdpcap(args.file)

text_data = []

# Define a function to print the contents of HTTP packets
for packet in packets:
    # Check if the packet has a Raw layer and extract the data
    if Raw in packet:
        data = packet[Raw].load
        # Split the data into lines and append them to the text_data list
        text_data.extend(data.splitlines())
        
# Call the function
for line in text_data:
    print(line)