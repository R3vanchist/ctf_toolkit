from scapy.all import *
import argparse


""" # Parse user input for source and destination IPs
parser = argparse.ArgumentParser(description="DNS traffic analysis for data exfiltration")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()

packets = rdpcap(args.file) """

def dns_exfil(packets, srcIP, dstIP):
    payload = []

    for packet in packets[DNS]:
        sourceIP = packet[IP].src
        destinationIP = packet[IP].dst
        qname = packet[DNSQR].qname
        try:
            if ( sourceIP == srcIP and destinationIP == dstIP ):
                queryName = qname.decode().split('.')
                if queryName[0] not in payload:
                    payload.append(queryName[0])
        except IndexError:
            continue
    print(''.join(payload))

