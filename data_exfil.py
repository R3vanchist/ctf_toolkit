from scapy.all import *
import sys


def search_pcap(pcap_file, src_ip, dst_ip, protocol):
    packets = rdpcap(pcap_file)
    for pkt in packets:
        if IP in pkt and pkt.haslayer(Raw):
            if pkt[IP].src == src_ip and pkt[IP].dst == dst_ip:
                if protocol == "UDP" and UDP in pkt:
                    print(pkt[Raw].load.decode("ascii"))
                    input()
                    # You can add more specific details of the packet as per your requirement
                elif protocol == "HTTP" and TCP in pkt:
                    print(pkt[Raw].load)
                    input()
                    # You can add more specific details of the packet as per your requirement
                elif protocol == "ICMP" and ICMP in pkt:
                    print(pkt[Raw].load.decode("ascii"))
                    input()
                    # You can add more specific details of the packet as per your requirement
            elif pkt[IP].src == dst_ip and pkt[IP].dst == src_ip:
                if protocol == "UDP" and UDP in pkt:
                    print(pkt[Raw].load.decode("ascii"))
                    input()
                    # You can add more specific details of the packet as per your requirement
                elif protocol == "HTTP" and TCP in pkt:
                    print(pkt[Raw].load)
                    input()
                    # You can add more specific details of the packet as per your requirement
                elif protocol == "ICMP" and ICMP in pkt:
                    print(pkt[Raw].load.decode("ascii"))
                    input()
                    # You can add more specific details of the packet as per your requirement

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: {} <pcap_file> <src_ip> <dst_ip>".format(sys.argv[0]))
        sys.exit(1)

    pcap_file = sys.argv[1]
    src_ip = sys.argv[2]
    dst_ip = sys.argv[3]
    
    protocol = input("Enter the protocol you want to search for (UDP/HTTP/ICMP): ").upper()

    search_pcap(pcap_file, src_ip, dst_ip, protocol)