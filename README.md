# CodeAlpha_N_sniffer
# Windows Network Packet Sniffer with Scapy

This project is a simple Python-based network packet sniffer that captures and displays Ethernet, IP, and TCP header information in real time using the **Scapy** library. It is tailored for use on **Windows**, leveraging **Npcap** for low-level packet access.

---

## ✅ Features

- Capture packets from a chosen network interface
- Show Ethernet (MAC), IP, and TCP headers
- Real-time output in the terminal
- Interactive interface selection at runtime

---

## ⚙️ Requirements

- **Python 3.7+**
- **Scapy**
- **Npcap** (with WinPcap compatibility mode)
- Administrator privileges

---

## 🔧 Installation Instructions

### 1. Install Python
Download and install Python from [https://www.python.org/downloads](https://www.python.org/downloads)

### 2. Install Npcap
Download and install Npcap from [https://nmap.org/npcap](https://nmap.org/npcap)

During installation, ensure you:
- ✅ Check "Install Npcap in WinPcap API-compatible Mode"
- ✅ Optionally check "Support raw 802.11 traffic" (for Wi-Fi sniffing)
- ❌ Do **not** install WinPcap if prompted separately

### 3. Install Scapy
Run this command in an **Administrator Command Prompt**:

```bash
pip install scapy
