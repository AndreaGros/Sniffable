from scapy.all import *

class Sniffer:
    def sniffing(interface=None, filters="", number=10):
        print("Start sniffing...")
        pkts = sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
        return pkts
    
    def viewComunicationRaw(self, com):
        print(com.summary())

    def InspectPacket(self, com, idPacket):
        print(com[idPacket])

s = Sniffer()

pkts = s.sniffing()
s.InspectPacket(pkts, 1)