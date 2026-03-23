# DOPO - con AsyncSniffer
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP, ICMP


class Sniffer:
    def __init__(self, iface=None, on_packet=None, bpf_filter=""):
        self.iface = iface
        self.on_packet = on_packet
        self.bpf_filter = bpf_filter
        self._sniffer = None

    def start(self):
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self.callbackPacket,
            store=False,
        )
        self._sniffer.start()
        print("Start sniffing")

    def stop(self):
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()

    def callbackPacket(self, pkt):
        if not pkt.haslayer(IP):
            return

        data = {
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": "Undefined",
            "info": "Undefined",
            "length": "Undefined",
        }

        if pkt.haslayer(TCP):
            data["proto"] = "TCP"
        elif pkt.haslayer(UDP):
            data["proto"] = "UDP"
        elif pkt.haslayer(ICMP):
            data["proto"] = "ICMP"

        data["length"] = str(len(pkt))

        if self.on_packet:
            self.on_packet(data)
