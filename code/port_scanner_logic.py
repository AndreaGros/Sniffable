
from scapy.all import Ether, ARP, sr, srp
from scapy.layers.inet import Ether, IP, ICMP, TCP, UDP


class Scanner:
    
    def ip_scan(self, target = "127.0.0.1", protoRange=[0, 255]):
        ans, unans =sr(IP(dst=target, proto=(protoRange[0], protoRange[1])) / "SCAPY", retry=2)
        for snd, rcv in ans:
            print(f"Protocol {snd.proto} answered from {rcv.src}")
    
    def device_scan(self, target="192.168.1.1/24"):
        ans, unans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target),
            timeout = 1,
            verbose=False
        )
        
        devices = []
        for sent, received in ans:
            device = {
                "ip": received[ARP].psrc,
                "mac": received[Ether].src
            }
            devices.append(device)
            print(f"IP: {device['ip']:<20} MAC: {device['mac']}")
        
        print(f"\Found {len(devices)} devices")
        return devices

    def ping(self, target = "127.0.0.1", nPkt=1):
        ans, unans = sr(IP(dst=target)/ICMP(), timeout=3)
        ans.summary(lambda s,r: r.sprintf("%IP.src% is alive") )

    

scan = Scanner()

scan.device_scan("192.168.1.1/24")