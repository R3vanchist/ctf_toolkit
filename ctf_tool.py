import argparse
from scapy.all import *
from udpExfil import udp_exfil
from icmpExfil import icmp_exfil
from userAgent import extract_user_agents
from httpExfil import print_http_packets


# Passing pcap as argument from command line
parser = argparse.ArgumentParser(description="UDP content dump.")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()

# Read the pcap
packets = rdpcap(args.file)

protocol = input("What are we looking for today?\nI accept: UDP, ICMP, HTTP, and User Agent: ").upper()

if protocol == "UDP":
    udp_exfil(packets)
elif protocol == "ICMP":
    icmp_exfil(packets)
elif protocol == "User Agent":
    extract_user_agents(packets)
elif protocol == "HTTP":
    print_http_packets(packets)
