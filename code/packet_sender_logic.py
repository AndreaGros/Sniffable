from scapy.all import Raw, sendp
from scapy.layers.inet import Ether, IP, ICMP, TCP, UDP


class Sender:

    def __init__(self, iface: str = None):
        self.iface = iface
        self.layers = []

    def reset(self):
        self.layers = []
        return self

    def add_ether(self, dst="ff:ff:ff:ff:ff:ff", src=None):
        kwargs = {"dst": dst}
        if src:
            kwargs["src"] = src
        self.layers.append(Ether(**kwargs))
        return self

    def add_ip(self, dst="127.0.0.1", src=None, ttl=64):
        kwargs = {"dst": dst, "ttl": ttl}
        if src:
            kwargs["src"] = src
        self.layers.append(IP(**kwargs))
        return self

    def add_tcp(self, dport=80, sport=None, flags="S", seq=None):
        kwargs = {"dport": dport, "flags": flags}
        if sport:
            kwargs["sport"] = sport
        if seq is not None:
            kwargs["seq"] = seq
        self.layers.append(TCP(**kwargs))
        return self

    def add_udp(self, dport=80, sport=None):
        kwargs = {"dport": dport}
        if sport:
            kwargs["sport"] = sport
        self.layers.append(UDP(**kwargs))
        return self

    def add_payload(self, data: str | bytes):
        if isinstance(data, str):
            data = data.encode()
        self.layers.append(Raw(load=data))
        return self

    def build_packet(self):
        if len(self.layers) == 0:
            print("Layers not found")
        else:
            print(self.layers)
            pkt = self.layers[0]
            for layer in self.layers[1:]:
                pkt = pkt / layer
        return pkt

    

    def send(self, pkt):
        if pkt:
            sendp(pkt)