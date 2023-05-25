from scapy.all import *

packets = rdpcap("dump.pcap")
print(packets[47][Raw].load)