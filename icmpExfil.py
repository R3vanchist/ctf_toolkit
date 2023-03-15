from scapy.all import *
import argparse


""" parser = argparse.ArgumentParser(description="PCAP Dissector for Data Exfiltration")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()


packets = rdpcap(args.file) """

def icmp_exfil(packets):
    for packet in packets:
        try:
            if packet.haslayer(ICMP) and packet.haslayer(Raw):
                payload = packet[Raw].load
                payload = payload.decode("ascii")
                print(f"Payload: {payload}")
        except IndexError:
            continue
