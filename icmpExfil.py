from scapy.all import *
import argparse


parser = argparse.ArgumentParser(description="PCAP Dissector for Data Exfiltration")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
parser.add_argument("-s", "--source", required=True, help="Source IP address")
parser.add_argument("-d", "--destination", required=True, help="Destination IP address")
args = parser.parse_args()


pcap = rdpcap(args.file)
for packet in pcap:
    if packet.haslayer(ICMP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        payload = payload.decode("ascii")
        if packet[IP].src == args.source and packet[IP].dst == args.destination:
            print(f"Payload: {payload}")
