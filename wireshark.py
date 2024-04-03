from scapy.all import *
import ipaddress
import sys

ports = [25, 80, 53, 443, 445, 8080, 8443]

def packet_handler(packet):
    if TCP in packet and IP in packet:
        if packet[TCP].dport in ports:
            print("Captured packet: ", packet.summary())

def SynScan(host):
    ans, unans = sr(
        IP(dst=host) /
        TCP(sport=33333, dport=ports, flags="S")
        , timeout=2, verbose=0)
    print("Open ports at %s:" % host)
    for (s, r,) in ans:
        if s[TCP].dport == r[TCP].sport and r[TCP].flags == "SA":
            print("Port:", s[TCP].dport)

def DNSScan(host):
    ans, unans = sr(
        IP(dst=host) /
        UDP(dport=53) /
        DNS(rd=1, qd=DNSQR(qname="google.com"))
        , timeout=2, verbose=0)
    if ans and ans[UDP]:
        print("DNS Server at %s" % host)

host = input("Enter IP Address: ")
try:
    ipaddress.ip_address(host)
except:
    print("Invalid address")
    sys.exit(-1)

# Start capturing packets in real-time
sniff(prn=packet_handler, store=0)

# Perform the port scanning after capturing packets
SynScan(host)
DNSScan(host)
