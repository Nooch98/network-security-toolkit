# network-security-toolkit

# 🛡️ IPv4/IPv6 Attack Detection

* **ARP Spoofing:**
* **How ​​it is detected:** The script analyzes ARP packets to detect potential conflicts.
If the router's IP address (or any device on the network) is associated with an unexpected MAC address in an ARP packet, the script generates an alert. It also has a proactive monitoring mode that periodically checks the system's ARP cache for suspicious changes to the router's MAC address.

* **ICMPv6 Spoofing:**
* **How ​​it is detected:** Similar to ARP snooping, the script monitors ICMPv6 Neighbor Discovery (ND) and Router Advertisement (RA) packets. If a device advertises itself as an IPv6 router (Gateway) with a MAC address that does not match the original MAC address of the legitimate router, an alert is generated.

* **DHCP Spoofing:**
* **How ​​it is detected:** The script examines DHCP packets. If a DHCP response packet comes from an IP address other than the router's or one that has not been previously identified as a trusted IP, it is considered a threat.

# 🌐 DNS and Web Attack Detection

* **DNS Spoofing:**
* **How ​​it is detected:** When a DNS query is made, the script captures the request and waits for the response. If the response contains an IP address that does not match the legitimate addresses for that domain (obtained through trusted DNS servers such as 8.8.8.8 or 1.1.1.1), an alert is generated. This prevents traffic from being redirected to malicious websites (may generate false positives).

* **SSLstrip:**
* **How ​​it is detected:** The script monitors HTTP traffic. If it detects an HTTP connection to a domain that you know should use HTTPS (such as Google, Amazon, etc.), it generates an alert. This indicates that an attacker may have removed the SSL/TLS encryption, rendering the connection insecure.

# 🔬 Additional Features

* **Active Countermeasures (`-c`):** This function allows the script to not only detect but also mitigate the attack. It sends gratuitous ARP and ND packets to restore the network tables, correcting entries altered by an attacker and restoring legitimate traffic flow.

# 💻 Script Usage

* **Simple Detection Mode:** To passively monitor the selected interface:
```bash
sudo python3 MITM_<LENGUEAGE>.py -i <Interface>
```
or you can use
```bash
sudo python3 MITM_<LENGUEAGE>.py -i <Interface> -p
```

* **Countermeasure Mode:** To monitor the selected interface and mitigate detected attacks:
```bash
sudo python3 MITM_<LENGUEAGE>.py -i <Interface> -c
```

* **Using Trusted IPs:** To monitor the network and list the IPs of trusted devices on the network:
```bash
sudo python3 MITM_<LENGUEAGE>.py -i <Interface> --trusted-ips 10.10.10.1,10.10.10.11
```

# ⚠️ Ethical and Legal Use Warning
This script is intended for ethical use on your own networks or with administrator authorization. Any unauthorized use of this script on a third-party network could be illegal and have legal consequences.

## 🛑 Limitations and Risks
The script uses active countermeasures to mitigate attacks. Although this is a very useful feature, it also poses some risks.

* **Network Outage Risk:** The countermeasures feature may generate significant network traffic or send ARP or ND packets, which, on poorly configured or highly sensitive networks, could cause a temporary service interruption.

* **False Positives:** Although every attempt is made to fine-tune accuracy, false alarms may occur, especially on complex networks or with atypical configurations. Therefore, any alert should be analyzed.

## 📜 Disclaimer

* **Disclaimer:** As the original creator of this script, I am not responsible for any misuse or damage caused by misuse of the script. As the user, you assume full responsibility.
