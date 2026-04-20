
from scapy.all import Ether, ARP, sr, srp
from scapy.layers.inet import Ether, IP, ICMP, TCP, UDP


class Scanner:
    
    def ip_scan(self, target = "127.0.0.1", protoRange=[0, 255]):
        ans, unans =sr(IP(dst=target, proto=(protoRange[0], protoRange[1])) / "SCAPY", retry=2)
        for snd, rcv in ans:
            print(f"Protocol {snd.proto} answered from {rcv.src}")
    
    def device_scan(self, target = "127.0.0.1"):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=2)
        ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )

scan = Scanner()

scan.device_scan("10.216.10.117")