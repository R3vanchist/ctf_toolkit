import argparse
from scapy.all import *
from udpExfil import udp_exfil
from icmpExfil import icmp_exfil


# Passing pcap as argument from command line
parser = argparse.ArgumentParser(description="UDP content dump.")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()

# Read the pcap
packets = rdpcap(args.file)

protocol = input("What protocol are we looking at in this pcap? ").upper()

if protocol == "UDP":
    udp_exfil(packets)
elif protocol == "ICMP":
    icmp_exfil(packets)
