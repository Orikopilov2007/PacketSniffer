import json
import os
import subprocess
import csv
import datetime
import threading
from collections import Counter, defaultdict
from scapy.all import sniff, wrpcap, rdpcap, get_if_list
from prettytable import PrettyTable
from colorama import init, Fore, Style

init(autoreset=True)

# === Globals ===
captured_packets = []
sniffing = False
ip_counter = {}

# === Packet Analysis ===

def analyze_packet(packet):
    captured_packets.append(packet)
    print_packet_summary(packet)

def print_packet_summary(packet):
    table = PrettyTable()
    table.field_names = ["Layer", "Attribute", "Value"]

    if packet.haslayer("Ether"): add_ethernet_info(packet, table)
    if packet.haslayer("IP"):    add_ip_info(packet, table)
    if packet.haslayer("TCP"):   add_tcp_info(packet, table)
    if packet.haslayer("UDP"):   add_udp_info(packet, table)
    if packet.haslayer("ICMP"):  add_icmp_info(packet, table)
    if packet.haslayer("DNS"):   add_dns_info(packet, table)
    if packet.haslayer("Raw"):   add_http_info(packet, table)

    print("\n" + Fore.BLUE + "========== New Packet ==========")
    print(table)
    print(Fore.BLUE + "================================\n")

def add_ethernet_info(packet, table):
    eth = packet.getlayer("Ether")
    table.add_row(["Ethernet", "Source MAC", eth.src])
    table.add_row(["Ethernet", "Destination MAC", eth.dst])
    table.add_row(["Ethernet", "Type", eth.type])

def add_ip_info(packet, table):
    ip = packet.getlayer("IP")
    src, dst = ip.src, ip.dst
    ip_counter[src] = ip_counter.get(src, 0) + 1
    table.add_row(["IP", "Source IP", src])
    table.add_row(["IP", "Destination IP", dst])
    table.add_row(["IP", "TTL", ip.ttl])
    table.add_row(["IP", "Protocol", ip.proto])
    table.add_row(["IP", "Packets from IP", ip_counter[src]])

def get_tcp_type(tcp):
    flags = tcp.flags
    if flags.S and flags.A: return "SYN-ACK"
    elif flags.S: return "SYN"
    elif flags.F: return "FIN"
    elif flags.R: return "RST"
    elif flags.A: return "ACK"
    return str(flags)

def add_tcp_info(packet, table):
    tcp = packet.getlayer("TCP")
    table.add_row(["TCP", "Type", get_tcp_type(tcp)])
    table.add_row(["TCP", "Src Port", tcp.sport])
    table.add_row(["TCP", "Dst Port", tcp.dport])
    table.add_row(["TCP", "Seq", tcp.seq])
    table.add_row(["TCP", "Ack", tcp.ack])
    table.add_row(["TCP", "Flags", str(tcp.flags)])
    table.add_row(["TCP", "Window", tcp.window])

def add_udp_info(packet, table):
    udp = packet.getlayer("UDP")
    table.add_row(["UDP", "Src Port", udp.sport])
    table.add_row(["UDP", "Dst Port", udp.dport])
    table.add_row(["UDP", "Length", udp.len])

def add_icmp_info(packet, table):
    icmp = packet.getlayer("ICMP")
    table.add_row(["ICMP", "Type", icmp.type])
    table.add_row(["ICMP", "Code", icmp.code])

def add_dns_info(packet, table):
    dns = packet.getlayer("DNS")
    table.add_row(["DNS", "Transaction ID", dns.id])
    table.add_row(["DNS", "QR", dns.qr])
    if dns.qr == 0 and dns.qdcount > 0:
        table.add_row(["DNS", "Query Name", dns.qd.qname.decode()])
    elif dns.an:
        table.add_row(["DNS", "Answer", str(dns.an.rdata)])

def add_http_info(packet, table):
    raw = packet.getlayer("Raw")
    try:
        data = raw.load.decode(errors="ignore")
        if "HTTP" in data or "GET" in data or "POST" in data:
            lines = data.split("\r\n")
            for line in lines[:5]:
                table.add_row(["HTTP", "", line])
    except:
        pass

# === Utility ===

def get_available_interfaces():
    return get_if_list()

def get_timestamped_filename(prefix, ext):
    now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{prefix}_{now}.{ext}"

def sniff_packets(count=0, timeout=None, bpf_filter=None):
    global sniffing
    sniffing = True
    interfaces = get_available_interfaces()
    print("\nAvailable interfaces:")
    for idx, iface in enumerate(interfaces):
        print(f"{idx+1}) {iface}")
    iface_index = input("Choose interface [number]: ").strip()
    iface = interfaces[int(iface_index)-1] if iface_index.isdigit() and 0 < int(iface_index) <= len(interfaces) else interfaces[0]

    sniff(prn=analyze_packet, store=False, count=count, timeout=timeout, filter=bpf_filter, iface=iface)
    sniffing = False

def save_to_csv(filename):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["No.", "Time", "IP Src", "IP Dst", "Protocol", "Type/Flags"])
        for i, pkt in enumerate(captured_packets, 1):
            ip_layer = pkt.getlayer("IP")
            tcp_type = get_tcp_type(pkt["TCP"]) if pkt.haslayer("TCP") else ""
            proto = ip_layer.proto if pkt.haslayer("IP") else ""
            row = [
                i,
                datetime.datetime.now().strftime('%H:%M:%S'),
                ip_layer.src if ip_layer else "",
                ip_layer.dst if ip_layer else "",
                proto,
                tcp_type
            ]
            writer.writerow(row)
    print(Fore.GREEN + f"\n✅ Saved to {filename}")

def save_to_pcap(filename):
    if captured_packets:
        wrpcap(filename, captured_packets)
        print(Fore.GREEN + f"✅ Packets saved to {filename}")

def save_to_json(filename):
    export = []
    for pkt in captured_packets:
        pkt_dict = {
            "timestamp": datetime.datetime.now().isoformat(),
            "ip_src": pkt["IP"].src if pkt.haslayer("IP") else "",
            "ip_dst": pkt["IP"].dst if pkt.haslayer("IP") else "",
            "protocol": pkt["IP"].proto if pkt.haslayer("IP") else "",
            "tcp_type": get_tcp_type(pkt["TCP"]) if pkt.haslayer("TCP") else "",
            "tcp_sport": pkt["TCP"].sport if pkt.haslayer("TCP") else "",
            "tcp_dport": pkt["TCP"].dport if pkt.haslayer("TCP") else "",
        }
        export.append(pkt_dict)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=4)
    print(Fore.GREEN + f"✅ Saved to {filename}")

def load_from_pcap(filename):
    global captured_packets
    try:
        captured_packets = rdpcap(filename)
        print(Fore.GREEN + f"✅ Loaded {len(captured_packets)} packets from {filename}")
    except Exception as e:
        print(Fore.RED + f"❌ Failed to read PCAP file: {e}")

def print_protocol_summary():
    proto_counts = Counter()
    total_size = 0
    for pkt in captured_packets:
        total_size += len(pkt)
        if pkt.haslayer("TCP"): proto_counts["TCP"] += 1
        elif pkt.haslayer("UDP"): proto_counts["UDP"] += 1
        elif pkt.haslayer("ICMP"): proto_counts["ICMP"] += 1
        elif pkt.haslayer("DNS"): proto_counts["DNS"] += 1
        elif pkt.haslayer("Raw"): proto_counts["HTTP/Raw"] += 1
        else: proto_counts["Other"] += 1

    print(Fore.YELLOW + "\n=== Protocol Statistics ===")
    for proto, count in proto_counts.items():
        print(f"{proto}: {count} packets")
    print(f"Total packets: {len(captured_packets)}")
    print(f"Total captured size: {total_size / 1024:.2f} KB")

def detect_syn_flood(threshold=10):
    syn_counts = defaultdict(int)
    for pkt in captured_packets:
        if pkt.haslayer("TCP") and pkt["TCP"].flags == "S":
            syn_counts[pkt["IP"].src] += 1
    for ip, count in syn_counts.items():
        if count > threshold:
            print(Fore.RED + f"⚠️  Potential SYN flood from {ip}: {count} SYN packets")

def export_stats_json(filename="stats.json"):
    stats = {
        "total_packets": len(captured_packets),
        "by_protocol": dict(Counter([
            "TCP" if pkt.haslayer("TCP") else
            "UDP" if pkt.haslayer("UDP") else
            "ICMP" if pkt.haslayer("ICMP") else
            "DNS" if pkt.haslayer("DNS") else
            "HTTP" if pkt.haslayer("Raw") else
            "Other"
            for pkt in captured_packets
        ])),
        "capture_time": datetime.datetime.now().isoformat()
    }
    with open(filename, "w") as f:
        json.dump(stats, f, indent=4)
    print(Fore.GREEN + f"📊 Stats exported to {filename}")

def filter_by_ip(ip):
    matches = [pkt for pkt in captured_packets if pkt.haslayer("IP") and (pkt["IP"].src == ip or pkt["IP"].dst == ip)]
    print(Fore.YELLOW + f"\n🔎 Found {len(matches)} packets for IP {ip}")
    for pkt in matches[:10]:  # מציג עד 10
        print_packet_summary(pkt)

def filter_by_port(port):
    matches = [pkt for pkt in captured_packets if (
        (pkt.haslayer("TCP") and (pkt["TCP"].sport == port or pkt["TCP"].dport == port)) or
        (pkt.haslayer("UDP") and (pkt["UDP"].sport == port or pkt["UDP"].dport == port))
    )]
    print(Fore.YELLOW + f"\n🔎 Found {len(matches)} packets for port {port}")
    for pkt in matches[:10]:
        print_packet_summary(pkt)

def detect_anomalies():
    for pkt in captured_packets:
        if pkt.haslayer("ICMP") and len(pkt) > 1500:
            print(Fore.RED + f"⚠️  Large ICMP packet ({len(pkt)} bytes) – possible Ping of Death.")
        if pkt.haslayer("TCP") and pkt["TCP"].dport > 49152:
            print(Fore.MAGENTA + f"⚠️  High TCP port: {pkt['TCP'].dport}")
        if pkt.haslayer("DNS") and pkt["DNS"].id > 1000:
            print(Fore.RED + f"⚠️  High DNS ID: {pkt['DNS'].id}")

# === Menu ===
def main_menu():
    while True:
        print(Fore.YELLOW + "\n=== Packet Sniffer Menu ===")
        print("1) Start live sniffing")
        print("2) Save to CSV")
        print("3) Save to PCAP")
        print("4) Load PCAP file")
        print("5) Save to JSON")
        print("6) Export stats to JSON")
        print("7) Filter packets by IP")
        print("8) Filter packets by Port")
        print("9) Exit")
        choice = input("Select [1-9]: ").strip()

        if choice == "1":
            try:
                count = input("Number of packets (0 = unlimited)? ").strip()
                timeout = input("Timeout in seconds (0 = none)? ").strip()
                bpf = input("Filter (e.g., 'tcp port 80', or leave blank): ").strip()
                count = int(count) if count.isdigit() else 0
                timeout = int(timeout) if timeout.isdigit() else None
                captured_packets.clear()

                thread = threading.Thread(target=sniff_packets, args=(count, timeout, bpf or None))
                thread.start()
                try:
                    thread.join()
                except KeyboardInterrupt:
                    print(Fore.YELLOW + "\n🛑 Sniffing interrupted by user.")
                    filename = get_timestamped_filename("interrupted_capture", "pcap")
                    save_to_pcap(filename)
                    print(Fore.YELLOW + f"💾 Partial capture saved to {filename}")

                print(Fore.CYAN + f"\n✅ Captured {len(captured_packets)} packets.")
                print_protocol_summary()
                detect_syn_flood()
                detect_anomalies()

            except Exception as e:
                print(Fore.RED + f"Error: {e}")

        elif choice == "2":
            save_to_csv(get_timestamped_filename("packets", "csv"))

        elif choice == "3":
            save_to_pcap(get_timestamped_filename("capture", "pcap"))

        elif choice == "4":
            file = input("Enter PCAP file path: ").strip()
            load_from_pcap(file)

        elif choice == "5":
            save_to_json(get_timestamped_filename("packets", "json"))

        elif choice == "6":
            export_stats_json(get_timestamped_filename("stats", "json"))
        
        elif choice == "7":
            ip = input("Enter IP to filter: ").strip()
            filter_by_ip(ip)

        elif choice == "8":
            port = input("Enter Port to filter: ").strip()
            if port.isdigit():
                filter_by_port(int(port))
            else:
                print(Fore.RED + "Invalid port.")

        elif choice == "9":
            print("👋 Bye!")
            break

        else:
            print("❌ Invalid choice.")
            
if __name__ == "__main__":
    main_menu()
