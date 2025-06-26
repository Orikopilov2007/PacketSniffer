import os
import subprocess
from scapy.all import sniff
from prettytable import PrettyTable
import threading
import csv
import datetime
from colorama import init, Fore, Style

init(autoreset=True)

ip_counter = {}
sniff_thread = None
sniffing = False
captured_packets = []

def analyze_packet(packet):
    captured_packets.append(packet)
    table = PrettyTable()
    table.field_names = ["Layer", "Attribute", "Value"]

    if packet.haslayer("Ether"): analyze_ethernet(packet, table)
    if packet.haslayer("IP"):    analyze_ip(packet, table)
    if packet.haslayer("TCP"):   analyze_tcp(packet, table)
    if packet.haslayer("UDP"):   analyze_udp(packet, table)
    if packet.haslayer("ICMP"):  analyze_icmp(packet, table)

    print("\n" + Fore.BLUE + "========== New Packet ==========" + Style.RESET_ALL)
    print(table)
    print(Fore.BLUE + "================================\n" + Style.RESET_ALL)

def analyze_ethernet(packet, table):
    eth = packet.getlayer("Ether")
    table.add_row([Fore.WHITE+"Ethernet"+Style.RESET_ALL,
                   Fore.YELLOW+"Source MAC"+Style.RESET_ALL,
                   Fore.CYAN+eth.src+Style.RESET_ALL])
    
    table.add_row([Fore.WHITE+"Ethernet"+Style.RESET_ALL,
                   Fore.YELLOW+"Destination MAC"+Style.RESET_ALL,
                   Fore.CYAN+eth.dst+Style.RESET_ALL])
    
    table.add_row([Fore.WHITE+"Ethernet"+Style.RESET_ALL,
                   Fore.YELLOW+"Type"+Style.RESET_ALL,
                   Fore.CYAN+str(eth.type)+Style.RESET_ALL])

def analyze_ip(packet, table):
    ip = packet.getlayer("IP")
    table.add_row([Fore.GREEN+"IP"+Style.RESET_ALL,
Fore.YELLOW+"Source IP"+Style.RESET_ALL,
                   Fore.MAGENTA+ip.src+Style.RESET_ALL])
    
    table.add_row([Fore.GREEN+"IP"+Style.RESET_ALL,
                   Fore.YELLOW+"Destination IP"+Style.RESET_ALL,
                   Fore.MAGENTA+ip.dst+Style.RESET_ALL])
    
    table.add_row([Fore.GREEN+"IP"+Style.RESET_ALL,
                   Fore.YELLOW+"TTL"+Style.RESET_ALL,
                   Fore.MAGENTA+str(ip.ttl)+Style.RESET_ALL])
    
    table.add_row([Fore.GREEN+"IP"+Style.RESET_ALL,
                   Fore.YELLOW+"Protocol"+Style.RESET_ALL,
                   Fore.MAGENTA+str(ip.proto)+Style.RESET_ALL])
    
    table.add_row([Fore.GREEN+"IP"+Style.RESET_ALL,
                   Fore.YELLOW+"Checksum"+Style.RESET_ALL,
                   Fore.MAGENTA+str(ip.chksum)+Style.RESET_ALL])
    
    ip_counter[ip.src] = ip_counter.get(ip.src, 0) + 1
    table.add_row([Fore.GREEN+"IP"+Style.RESET_ALL,
                   Fore.YELLOW+f"Packets from {ip.src}"+Style.RESET_ALL,
                   Fore.MAGENTA+str(ip_counter[ip.src])+Style.RESET_ALL])

def get_tcp_type(tcp):
    flags = tcp.flags
    if flags.S and flags.A:
        return "SYN-ACK"
    elif flags.S:
        return "SYN"
    elif flags.F:
        return "FIN"
    elif flags.R:
        return "RST"
    elif flags.A:
        return "ACK"
    else:
        return str(flags)

def analyze_tcp(packet, table):
    tcp = packet.getlayer("TCP")
    pkt_type = get_tcp_type(tcp)

    # Coloring TCP fields for 3 way handshake
    layer_col = Fore.CYAN + "TCP" + Style.RESET_ALL
    attr_col  = Fore.YELLOW + "Type" + Style.RESET_ALL
    val_col   = Fore.RED + pkt_type + Style.RESET_ALL
    table.add_row([layer_col, attr_col, val_col])

    table.add_row([layer_col,
                   Fore.YELLOW+"Source Port"+Style.RESET_ALL,
                   Fore.GREEN+str(tcp.sport)+Style.RESET_ALL])
    
    table.add_row([layer_col,
                   Fore.YELLOW+"Destination Port"+Style.RESET_ALL,
                   Fore.GREEN+str(tcp.dport)+Style.RESET_ALL])
    
    table.add_row([layer_col,
                   Fore.YELLOW+"Sequence"+Style.RESET_ALL,
                   Fore.WHITE+str(tcp.seq)+Style.RESET_ALL])
    
    table.add_row([layer_col,
                   Fore.YELLOW+"Ack"+Style.RESET_ALL,
                   Fore.WHITE+str(tcp.ack)+Style.RESET_ALL])
    
    table.add_row([layer_col,
                   Fore.YELLOW+"Flags"+Style.RESET_ALL,
                   Fore.WHITE+str(tcp.flags)+Style.RESET_ALL])
    
    table.add_row([layer_col,
                   Fore.YELLOW+"Window"+Style.RESET_ALL,
                   Fore.WHITE+str(tcp.window)+Style.RESET_ALL])
    
    table.add_row([layer_col,
                   Fore.YELLOW+"Checksum"+Style.RESET_ALL,
                   Fore.WHITE+str(tcp.chksum)+Style.RESET_ALL])

def analyze_udp(packet, table):
    udp = packet.getlayer("UDP")
    table.add_row(["UDP", "Source Port", udp.sport])
    table.add_row(["UDP", "Destination Port", udp.dport])
    table.add_row(["UDP", "Length", udp.len])
    table.add_row(["UDP", "Checksum", udp.chksum])

def analyze_icmp(packet, table):
    icmp = packet.getlayer("ICMP")
    table.add_row(["ICMP", "Type", icmp.type])
    table.add_row(["ICMP", "Code", icmp.code])
    table.add_row(["ICMP", "Checksum", icmp.chksum])

def sniff_packets(count):
    global sniffing
    sniffing = True
    sniff(prn=analyze_packet, store=False, count=count)
    sniffing = False

def save_packets_to_csv(packets, filename="packets.csv"):
    with open(filename, mode='w', encoding='utf-8-sig', newline='') as f:
        fieldnames = [
            "No.", "Timestamp",
            "Eth Src", "Eth Dst",
            "IP Src", "IP Dst",
            "Proto",
            "TCP Type",
            "TCP Src Port", "TCP Dst Port",
            "UDP Src Port", "UDP Dst Port",
            "ICMP Type", "ICMP Code"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for idx, pkt in enumerate(packets, start=1):
            tcp_type = get_tcp_type(pkt["TCP"]) if pkt.haslayer("TCP") else ""
            row = {
                "No.": idx,
                "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Eth Src": pkt.src if pkt.haslayer("Ether") else "",
                "Eth Dst": pkt.dst if pkt.haslayer("Ether") else "",
                "IP Src": pkt["IP"].src if pkt.haslayer("IP") else "",
                "IP Dst": pkt["IP"].dst if pkt.haslayer("IP") else "",
                "Proto": pkt["IP"].proto if pkt.haslayer("IP") else "",
                "TCP Type": tcp_type,
                "TCP Src Port": pkt["TCP"].sport if pkt.haslayer("TCP") else "",
                "TCP Dst Port": pkt["TCP"].dport if pkt.haslayer("TCP") else "",
                "UDP Src Port": pkt["UDP"].sport if pkt.haslayer("UDP") else "",
                "UDP Dst Port": pkt["UDP"].dport if pkt.haslayer("UDP") else "",
                "ICMP Type": pkt["ICMP"].type if pkt.haslayer("ICMP") else "",
                "ICMP Code": pkt["ICMP"].code if pkt.haslayer("ICMP") else "",
            }
            writer.writerow(row)

    try:
        if os.name == 'nt':
            os.startfile(filename)
        else:
            subprocess.run(['xdg-open', filename], check=False)
    except Exception as e:
        print(f"Could not open the file: {e}")

#MAIN LOOP
while True:
    print("Menu:\n 1) Start sniffing\n 2) Save last capture to CSV\n 3) Exit")
    choice = input("Choose [1-3]: ").strip()

    if choice == '1':
        if sniffing:
            print("Already sniffing!\n")
            continue
        n = input("How many packets to sniff? ")
        if not n.isdigit():
            print("Please enter a number.\n")
            continue
        count = int(n)
        captured_packets.clear()
        sniff_thread = threading.Thread(target=sniff_packets, args=(count,))
        sniff_thread.start()
        sniff_thread.join()
        print(f"Captured {len(captured_packets)} packets.\n")

    elif choice == '2':
        if not captured_packets:
            print("No packets captured yet.\n")
            continue
        save_packets_to_csv(captured_packets)
        print("Packets saved and CSV opened.\n")

    elif choice == '3':
        print("Goodbye!")
        if sniffing and sniff_thread:
            sniff_thread.join(timeout=1)
        break

    else:
        print("Invalid choice, try again.\n")
        continue
