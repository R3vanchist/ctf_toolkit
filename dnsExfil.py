from scapy.all import *
import argparse

# Not working yet

# Parse user input for source and destination IPs
parser = argparse.ArgumentParser(description="DNS traffic analysis for data exfiltration")
parser.add_argument("-s", "--source", required=True, help="Source IP address")
parser.add_argument("-d", "--destination", required=True, help="Destination IP address")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()

# Define filter for DNS traffic with specified source and destination IPs
dns_filter = "udp and src host {} and dst host {} and dst port 53".format(args.source, args.destination)

# Define function to dissect DNS packets
def dns_dissect(packet):
    # Check if packet has DNS layer
    if packet.haslayer(DNS):
        # Extract relevant DNS fields
        query_name = packet[DNSQR].qname.decode()
        query_type = packet[DNSQR].qtype
        response_code = packet[DNS].rcode
        response_data = packet[DNS].an.exchange.decode()

        # Check for possible data exfiltration
        if query_type == 1 and response_code == 0 and response_data != "":
            print("[+] Possible data exfiltration detected!")
            print("    Query name: {}".format(query_name))
            print("    Response data: {}".format(response_data))
            print()
            
# Load pcap file and start packet dissection with DNS filter and dissect function
packets = rdpcap(args.file)
for packet in packets:
    dns_dissect(packet)
