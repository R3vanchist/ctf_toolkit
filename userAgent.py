from scapy.all import *
from scapy.layers.http import HTTPRequest
import argparse


parser = argparse.ArgumentParser(description="Displays user agents")
parser.add_argument("-f", "--file", required=True, help="PCAP file to analyze")
args = parser.parse_args()

# Open the pcap file
packets = rdpcap(args.file)

# Define a function to extract user agents
def extract_user_agents(packets):
    user_agents = []
    for packet in packets:
        if HTTPRequest in packet:
            user_agent = packet[HTTPRequest].User_Agent
            if user_agent not in user_agents:
                user_agents.append(user_agent)
    return user_agents

# Call the function and print the results
user_agents = extract_user_agents(packets)
print("User Agents:")
for user_agent in user_agents:
    print(user_agent)
    
