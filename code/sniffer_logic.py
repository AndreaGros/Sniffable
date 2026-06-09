# DOPO - con AsyncSniffer
from scapy.all import AsyncSniffer, wrpcap, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from datetime import datetime
from scapy.arch.common import compile_filter


class Sniffer:

    def __init__(
        self,
        on_packet=None,
    ):
        self.index = 0
        self.packets = {}
        self.on_packet = on_packet
        self._sniffer = None

    def start(self, filterUser="", ifaceUser=""):
        print(ifaceUser)
        if filterUser:
            try:
                compile_filter(filterUser)
            except Exception as e:
                raise ValueError(f"Filtro BPF non valido: {e}")
            
        if ifaceUser and ifaceUser not in get_if_list():
            raise ValueError(f"Interfaccia non trovata: {ifaceUser}")
        self._sniffer = AsyncSniffer(
            iface=ifaceUser,
            filter=filterUser,
            prn=self.callbackPacket,
            store=False,
        )
        self._sniffer.start()
        print("Start sniffing")

    def stop(self):
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
            print("Stop sniffer")

    def callbackPacket(self, pkt):

        self.index += 1

        data = {
            "index": str(self.index),
            "src": "N/A",
            "dst": "N/A",
            "proto": "Undefined",
            "info": "",
            "length": str(len(pkt)),
        }

        # ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]

            data["proto"] = "ARP"

            data["sender_ip"] = arp.psrc
            data["sender_mac"] = arp.hwsrc
            data["target_ip"] = arp.pdst
            data["target_mac"] = arp.hwdst

            if arp.op == 1:
                data["info"] = f"ARP Request: Who has {arp.pdst}?"
            elif arp.op == 2:
                data["info"] = f"ARP Reply: {arp.psrc} is at {arp.hwsrc}"

        # IP
        elif pkt.haslayer(IP):

            data["src"] = pkt[IP].src
            data["dst"] = pkt[IP].dst

            # TCP
            if pkt.haslayer(TCP):
                data["proto"] = "TCP"
                data["info"] = str(pkt[TCP].flags)

            # DNS
            elif pkt.haslayer(DNS):
                dns = pkt[DNS]
                data["proto"] = "DNS"

                if dns.qr == 0 and dns.qd:
                    try:
                        data["info"] = dns.qd.qname.decode()
                    except:
                        data["info"] = "DNS Query"
                else:
                    data["info"] = "DNS Response"

            # UDP
            elif pkt.haslayer(UDP):
                data["proto"] = "UDP"

            # ICMP
            elif pkt.haslayer(ICMP):
                data["proto"] = "ICMP"

        else:
            return

        if self.on_packet:
            self.on_packet(data)
        self.packets[str(self.index)] = pkt

    def selectSinglePacket(self, index):
        pkt = self.packets[str(index)]
        result = {}

        # Informazioni generali
        layers = []
        current = pkt

        while current and current.__class__.__name__ != "NoPayload":
            layers.append(current.__class__.__name__)
            current = current.payload

        result["layers"] = layers
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

        # Payload grezzo
        if pkt.haslayer("Raw"):
            raw = pkt["Raw"].load
            result["raw_hex"] = raw.hex()
            result["raw_text"] = raw.decode("utf-8", errors="replace")

        return result

    def downloadCom(self, pkts):
        filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(filename, pkts.values())
        return filename
