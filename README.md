# network-security-toolkit

# 🛡️ MITMGuard

**MITMGuard** is a real-time Man-in-the-Middle (MitM) attack detection and countermeasure tool.  
It monitors ARP/ND spoofing, DNS spoofing, SSL stripping, rogue gateways, suspicious floods, and more.  
The tool can also apply countermeasures, isolate attackers, and export alerts for further analysis.  

MITMGuard is available in **English and Spanish**, selectable at runtime.

---

## ✨ Features

- ✅ Detects ARP and ND spoofing  
- ✅ Detects DNS spoofing and SSL stripping attempts  
- ✅ Detects rogue gateways and multiple router announcements  
- ✅ Flood/DoS anomaly detection  
- ✅ Device fingerprinting (TTL, TCP window, DHCP client ID, HTTP UA)  
- ✅ Optional countermeasures
- ✅ JSONL export of alerts for SIEM/analysis  
- ✅ Rich TUI (interactive interface with filters and pagination)  
- ✅ Dual language support (English / Spanish)  

---

## ⚙️ Installation

### Requirements
- Python 3.13+  
- Dependencies:  
  ```bash
  pip install scapy rich dnspython colorama keyboard
  ```

### Build as executable (Optional)
```bash
pyinstaller --onefile --icon "logo.ico" --name MITMGuard .\MITMGuard.py --add-data "MITMGuard_Spanish.py;." --add-data "MITMGuard_English.py;." --add-data "logo.ico;." --hidden-import "keyboard" --hidden-import "requests" --hidden-import "colorama" --hidden-import "rich" --hidden-import "scapy" --hidden-import "matplotlib" --hidden-import "networkx" --hidden-import "scapy.all" --hidden-import "dnspython" --hidden-import "dns" --hidden-import "dns.resolver" --add-data "tracker_domains.txt;."
```
It is recommended to add to the path.

## 🚀 Usage

### Basic detection
```PowerShell
python MITMGuard.py -i <interface>
```

### With countermeasures
```PowerShell
python MITMGuard.py -i <interface> -c/--countermeasures
```

### Pasive mode (No active scans)
```PowerShell
python MITMGuard.py -i <interface> -p/--pasive
```

### Select Language
```PowerShell
python MITMGuard.py -i <interface> -l es # Spanish
python MITMGuard.py -i <interface> -l en # English
```

### Clean generate files
```PowerShell
python MITMGuard.py -i <interface> -C/--clean
```
This removes logs, pcaps, JSONL alerts, and the network diagram.

---

## 📂 Generated Files
* `alerts.jsonl` -> Alerts in JSONL format
* `*.pcap` -> Captured malicius packets
* `mitm_debug.log` / `mitm_detector.log` -> Debug and detection logs
* `network_diagram.png` -> network map export

---

## ⚠️ Disclaimer

MITMGuard is designed for educational and defensive purposes only.
Do not use this tool on networks you do not own or have explicit permission to test.
As the author, I am not responsible for any misuse.
