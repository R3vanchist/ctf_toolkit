from scapy.all import *
import argparse

# Passing pcap as argument from command line
parser = argparse.ArgumentParser(description="UDP content dump.")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()
# Read the pcap
packets = rdpcap(args.file)
# Variable to hold the UDP data
contents = []
# Go through the pcap and pull all the raw data and append it to contents
for packet in packets[UDP]:
    try:
        if packet.haslayer(Raw):
            contents.append(packet[Raw].load)
    except IndexError:
        continue
# Print out contents
print(contents)
            
