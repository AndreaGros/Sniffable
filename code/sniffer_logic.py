from scapy.all import *

def sniffing(interface=None, filters="", number=10):
    print("Start sniffing...")
    pkts = sniff(
        prn=lambda x: x.sprintf("{IP:%IP.src% -> %IP.dst%}"),
    )
    return pkts