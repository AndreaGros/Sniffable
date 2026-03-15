from scapy.all import *
import threading

class Sniffer:
    def __init__(self, iface="eth0", on_packet=None, bpf_filter=""):
        self.iface = iface
        self.on_packet = on_packet
        self.bpf_filter = bpf_filter
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self.sniffing, daemon=True)
        self._thread.start()

    def sniffing(self):
        print("Start sniffing...")
        pkts = sniff(prn=self.callbackPacket)
        return pkts

    def callbackPacket(self, pkt):
        if self.on_packet:
            self.on_packet(pkt)

    def viewComunicationRaw(self, com):
        print(com.summary())

    def InspectPacket(self, com, idPacket):
        print(com[idPacket])