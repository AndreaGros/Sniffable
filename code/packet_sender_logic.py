from scapy.all import sendp
from scapy.layers.inet import Ether, IP, ICMP, TCP, UDP


class Sender:
    layers = []

    def __init__(self):
        print("init")

    def createPacket(self, params):
        print(params)
        if "eth" in params:
            self.layers.append(Ether(dst=params.eth.dst))

        if "ip" in params:
            self.layers.append(IP(dst=params["ip"]["dst"]))

        if "tcp" in params:
            self.layers.append(TCP(dport=params.tcp.dport, flags=params.tcp.flags))

        if "udp" in params:
            self.layers.append(UDP())

        print(self.layers)
        pkt = self.layers[0]
        for layer in self.layers[1:]:
            pkt = pkt / layer


layers = {"ip": {
    "dst":"8.8.8.8"
}}

s = Sender()

s.createPacket(params=layers)
