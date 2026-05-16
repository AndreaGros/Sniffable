from scapy.all import *
from scapy.all import Ether, ARP, sr, srp
from scapy.layers.inet import Ether, IP, ICMP, TCP, UDP


class Scanner:

    def ip_scan(self, target="127.0.0.1", protoRange=[0, 255]):
        ans, unans = sr(
            IP(dst=target, proto=(protoRange[0], protoRange[1])) / "SCAPY", retry=2
        )
        for snd, rcv in ans:
            print(f"Protocol {snd.proto} answered from {rcv.src}")

    def device_scan(self, target="192.168.1.0/24"):
        ans, unans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target), timeout=3, verbose=False
        )

        devices = []
        for sent, received in ans:
            device = {"ip": received[ARP].psrc, "mac": received[Ether].src}
            devices.append(device)
            print(f"IP: {device['ip']:<20} MAC: {device['mac']}")

        print(f"Found {len(devices)} devices")
        return devices

    def ping(self, target="127.0.0.1", nPkt=1):
        ans, unans = sr(IP(dst=target) / ICMP(), timeout=3)
        ans.summary(lambda s, r: r.sprintf("%IP.src% is alive"))

    def port_scan(self, target, startPort, endPort):
        open_ports = []

        for x in range(startPort, endPort+1):
            packet = IP(dst=target) / TCP(dport=x, flags="S")
            response = sr1(packet, timeout=0.5, verbose=0)
            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    print(f"Port {x} is open!")
                    open_ports.append(x)
                    send(IP(dst=target)/TCP(dport=x, flags="R"), verbose=0)

        return open_ports

scanner = Scanner()

scanner.port_scan(target="192.168.1.1", startPort=80, endPort=443)