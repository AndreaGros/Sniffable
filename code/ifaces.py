from scapy.all import get_if_list, get_if_addr

def get_interfaces():
    interfaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            interfaces.append({"name": iface, "ip": ip})
        except:
            pass
    return interfaces