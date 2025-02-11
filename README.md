# 👃 Scapy Packet Sniffer GUI

## 📝 Overview
This is a **Packet Sniffer GUI** built using **Python, PySide6, and Scapy**. It allows users to monitor network packets based on selected protocols (TCP, UDP, or ARP), set a specific packet count to capture, and optionally save the captured packets to a `.pcap` file.

## ✨ Features
- ✅ **Protocol Selection**: Choose between TCP, UDP, or ARP for packet sniffing.
- 🔢 **Packet Count Control**: Set the number of packets to capture.
- 💾 **Save to File**: Option to save captured packets as a `.pcap` file.
- 🖥️ **GUI Interface**: Simple and interactive UI built with PySide6.
- 📡 **Live Packet Display**: Captured packets are displayed in real-time.

## 🚀 Quick Start Guide

### 📦 Install Dependencies
Ensure you have the necessary dependencies installed. If you have a `requirements.txt` file, you can install all dependencies with:

```sh
pip install -r requirements.txt
```

Or manually install them with:
```sh
pip install scapy PySide6
```

### ▶️ How to Run
1. Clone the repository or download the script.
2. Ensure dependencies are installed.
3. Run the script using:

```sh
python sniffer.py
```

## 🛠️ Usage
1. 🛑 Select a protocol (TCP, UDP, or ARP).
2. 🔄 Set the number of packets to capture.
3. 🎯 Click **Run Sniffer** to start capturing packets.
4. 💾 (Optional) Enable "Save to File" to store packets in a `.pcap` file.
5. 🔁 Click **Reset** to clear inputs and start over.

## ⚠️ Notes
- 🔐 Ensure you have the necessary permissions to sniff packets on your system.
- 🌍 The sniffer runs on interface `en0` by default; modify this in the `sniff()` function if needed.
  - The console will display available interfaces, you may need to adjust to the one you're intending to scan

## 📜 License
This project is licensed under the MIT License.



