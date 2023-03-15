from scapy.all import *
from scapy.layers.http import HTTPRequest
import argparse

""" # Pass the pcap as an argument
parser = argparse.ArgumentParser(description="Displays user agents")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()

# Read the pcap file
packets = rdpcap(args.file) """

# Extract user agents
def extract_user_agents(packets):
    user_agents = []
    for packet in packets:
        if HTTPRequest in packet:
            user_agent = packet[HTTPRequest].User_Agent
            if user_agent not in user_agents:
                user_agents.append(user_agent)
    for user_agent in user_agents:
        print(f'User Agents: {user_agents}')

    
