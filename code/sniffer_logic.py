# DOPO - con AsyncSniffer
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP, ICMP


class Sniffer:

    index = 0
    packets = {}

    def __init__(self, iface=None, on_packet=None, bpf_filter=""):
        self.iface = iface
        self.on_packet = on_packet
        self.bpf_filter = bpf_filter
        self._sniffer = None

    def start(self):
        print(self.bpf_filter)
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

        self.index += 1

        data = {
            "index": str(self.index),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "proto": "Undefined",
            "info": "Undefined",
            "length": "Undefined",
        }

        if pkt.haslayer(TCP):
            data["proto"] = "TCP"
            data["info"] = str(pkt[TCP].flags)
        elif pkt.haslayer(UDP):
            data["proto"] = "UDP"
        elif pkt.haslayer(ICMP):
            data["proto"] = "ICMP"

        data["length"] = str(len(pkt))

        if self.on_packet:
            self.on_packet(data)
            self.packets[str(self.index)] = pkt

    def selectSinglePacket(self, index):
        pkt = self.packets[str(index)]
        result = {}

        # Informazioni generali
        result["layers"] = [layer.name for layer in pkt.layers()]
        result["length"] = len(pkt)
        result["time"] = str(pkt.time)

        # Layer Ethernet
        if pkt.haslayer("Ether"):
            result["eth_src"] = pkt["Ether"].src
            result["eth_dst"] = pkt["Ether"].dst

        # Layer IP
        if pkt.haslayer("IP"):
            result["ip_src"] = pkt["IP"].src
            result["ip_dst"] = pkt["IP"].dst
            result["ip_ttl"] = pkt["IP"].ttl
            result["ip_proto"] = pkt["IP"].proto

        # Layer TCP
        if pkt.haslayer("TCP"):
            result["tcp_sport"] = pkt["TCP"].sport
            result["tcp_dport"] = pkt["TCP"].dport
            result["tcp_flags"] = str(pkt["TCP"].flags)
            result["tcp_seq"] = pkt["TCP"].seq

        # Layer UDP
        if pkt.haslayer("UDP"):
            result["udp_sport"] = pkt["UDP"].sport
            result["udp_dport"] = pkt["UDP"].dport
            result["udp_len"] = pkt["UDP"].len

        # Payload grezzo (se presente)
        if pkt.haslayer("Raw"):
            raw = pkt["Raw"].load
            result["raw_hex"] = raw.hex()
            result["raw_text"] = raw.decode("utf-8", errors="replace")

        print(result)
        return result
