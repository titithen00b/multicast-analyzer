from scapy.all import rdpcap, Ether, IP
from collections import Counter
import sys

def is_multicast(mac):
    if not mac:
        return False
    return bool(int(mac.split(":")[0], 16) & 1)

def analyze_multicast(pcap_file):
    print(f"\nAnalyse du fichier : {pcap_file}")
    packets = rdpcap(pcap_file)
    multicast_sources = Counter()
    protocols = Counter()
    skipped = 0

    for pkt in packets:
        if Ether in pkt:
            dst_mac = pkt[Ether].dst
            if is_multicast(dst_mac):
                src_mac = pkt[Ether].src or "UNKNOWN"
                multicast_sources[src_mac] += 1

                if IP in pkt:
                    proto = pkt[IP].proto
                    protocols[proto] += 1
        else:
            skipped += 1

    print(f"\n⏭️ Paquets ignorés : {skipped}")

    print("\n📊 Top 10 sources multicast :")
    for mac, count in multicast_sources.most_common(10):
        print(f"{mac} : {count} paquets")

    print("\n🔎 Protocoles IP multicast (par numéro de protocole) :")
    for proto, count in protocols.items():
        print(f"Proto {proto} : {count} paquets")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage : python analyze_multicast.py fichier.pcap")
    else:
        analyze_multicast(sys.argv[1])
