# 🕵️‍♂️ Python Network Packet Sniffer

A full-featured command-line packet sniffer written in Python using **Scapy**. This tool enables real-time packet capture, protocol analysis, anomaly detection, and export to multiple formats.

---

## 🚀 Features

- 📡 **Live packet sniffing** from any network interface
- 📋 **Detailed packet breakdown**: Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP
- 🧠 **Protocol statistics** and **source IP counters**
- 🛡 **Security analysis**:
  - SYN flood detection
  - Large ICMP (e.g. Ping of Death)
  - Suspicious DNS / high ports
- 🧪 **Filtering by IP or Port**
- 💾 **Export support**:
  - CSV
  - JSON
  - PCAP (Wireshark compatible)
- 📂 **Load PCAP files** for analysis
- 🧵 Multithreaded sniffing with graceful exit and autosave on `Ctrl+C`
- 🎨 Colored output and pretty tables for clear terminal display

---

## ⚙️ Requirements

- Python 3.6+
- [Scapy](https://scapy.net)
- `colorama`, `prettytable`

Install dependencies:

```bash
pip install -r requirements.txt
