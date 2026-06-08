from scapy.all import sr1, IP, ICMP
import logging
from concurrent.futures import ThreadPoolExecutor

# Disattiva i log fastidiosi di Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def scan_ip(ip):
    """Funzione che scansiona un singolo IP"""
    # Usiamo sr1 che aspetta SOLO una risposta e si ferma subito
    # Un timeout di 0.5 o 1 secondo in una rete locale diretta è più che sufficiente
    packet = IP(dst=ip)/ICMP()
    reply = sr1(packet, timeout=0.8, verbose=False)
    
    if reply:
        print(f"[+] Host attivo: {ip}")
        return ip
    return None

def main():
    base_net = "192.168.1.0"
    # Creiamo la lista di tutti gli IP da .1 a .254
    ips = [f"{base_net}{i}" for i in range(1, 255)]
    
    print(f"Inizio Ping Sweep ICMP multithread su {base_net}0/24...")
    
    # Lanciamo fino a 50 thread contemporaneamente. 
    # Questo abbatte i tempi morti dei timeout!
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_ip, ips)

if __name__ == "__main__":
    import time
    start = time.time()
    main()
    print(f"Scansione completata in {time.time() - start:.1f} secondi.")