from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading


class Sniffer:
    def __init__(self, iface="eth0", on_packet=None, bpf_filter=""):
        self.iface = iface
        self.on_packet = on_packet
        self.bpf_filter = bpf_filter
        self._running = False
        self._thread = None
        self.stop_sniffer = threading.Event()

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self.sniffing, daemon=True)
        self._thread.start()

    def stop(self):
        self.stop_sniffer.set()

    def sniffing(self):
        print("Start sniffing...")
        pkts = sniff(prn=self.callbackPacket)
        return pkts

    def callbackPacket(self, pkt):
        if not pkt.haslayer(IP):
            return 
        
        data = {
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": "Undefined",
            "info": f"prova",
            "length": "prova"
        }

        if pkt.haslayer(TCP):
            data["proto"]="TCP"
        elif pkt.haslayer(UDP):
            data["proto"]="UDP"
        elif pkt.haslayer(ICMP):
            data["proto"]="ICMP"
        
        if self.on_packet:
            self.on_packet(data)

    def viewComunicationRaw(self, com):
        print(com.summary())

    def InspectPacket(self, com, idPacket):
        print(com[idPacket])
