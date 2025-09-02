import argparse
import logging
import os
import sys
import threading
import time
import io
from colorama import Fore, Style, init
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.syntax import Syntax
from scapy.all import (ARP, DNS, Ether, ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6ND_NS, IPv6, IP,
                       sniff, sendp, get_if_addr, get_if_hwaddr, conf, srp, wrpcap)
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, TCP
from scapy.layers.l2 import getmacbyip
from scapy.layers.http import HTTPRequest
from scapy.layers.dhcp import BOOTP, DHCP
import dns.resolver

# Initialize colorama for Windows support
init(autoreset=True)

class MitMDetection:
    def __init__(self, interface, trusted_ips=[], countermeasures=False, passive_mode=False, test_mode=False):
        self.interface = interface
        self.trusted_ips = set(trusted_ips)
        self.countermeasures = countermeasures
        self.passive_mode = passive_mode
        self.active = True
        self.test_mode = test_mode
        
        # UI related variables
        self.console = Console()
        self.alerts = []
        self.packet_count = 0
        self.ui_lock = threading.Lock()
        self.recent_malicious_packet = None

        try:
            self.my_ip = get_if_addr(self.interface)
            self.my_mac = get_if_hwaddr(self.interface)
        except Exception:
            self.my_ip = None
            self.my_mac = None

        self.my_ipv6_local = self._get_local_ipv6_for_interface()
        
        try:
            self.gateway_ip_v4 = conf.route.route("0.0.0.0")[2]
            self.gateway_mac_v4 = getmacbyip(self.gateway_ip_v4)
        except Exception:
            self.gateway_ip_v4 = None
            self.gateway_mac_v4 = None
        
        self.gateway_ip_v6 = None
        self.gateway_mac_v6 = None
        
        self.arp_table = {}
        self.neighbor_table = {}
        self.dns_queries = {}
        self.dns_responses = {}
        
        if self.my_ip:
            self.trusted_ips.add(self.my_ip)
        if self.my_ipv6_local:
            self.trusted_ips.add(self.my_ipv6_local)
        if self.gateway_ip_v4:
            self.trusted_ips.add(self.gateway_ip_v4)

        self.secure_domains = ["google.com", "facebook.com", "github.com", "microsoft.com", "amazon.com"]

        self._setup_logging()

    def _get_local_ipv6_for_interface(self):
        """Gets the Link-Local IPv6 address for the specified interface."""
        try:
            from scapy.all import get_if_list
            for iface_info in get_if_list():
                if 'name' in iface_info and iface_info['name'] == self.interface:
                    if 'ipv6_addrs' in iface_info and iface_info['ipv6_addrs']:
                        for addr in iface_info['ipv6_addrs']:
                            if addr.startswith('fe80::'):
                                return addr.split('%')[0]
            return None
        except Exception:
            return None

    def _setup_logging(self):
        """Configures the logging system for the console and file."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            filename='mitm_detector.log',
            filemode='a'
        )

    def log_malicious_packet(self, packet, alert_type):
        """
        Saves the packet that caused the alert to a .pcap file for later analysis.
        """
        filename = f"{alert_type.lower()}_alerts.pcap"
        wrpcap(filename, packet, append=True)
        logging.warning(f"[!] Malicious packet logged to '{filename}'.")

    def log_alert(self, alert_type, message, details, packet=None):
        """Displays an alert in the console (UI), logs it, and saves the packet if provided."""
        alert_text = f"[{alert_type}] {message} -> {details}"
        with self.ui_lock:
            self.alerts.insert(0, (time.strftime("%H:%M:%S"), alert_text))
            self.alerts = self.alerts[:10]
        
        logging.critical(f"ALERT: {alert_type} - {message} -> {details}")
        
        if packet:
            self.log_malicious_packet(packet, alert_type)
            self.recent_malicious_packet = packet

    def discover_system_dns(self):
        """Reads DNS servers directly from the operating system configuration."""
        try:
            resolver = dns.resolver.Resolver()
            for server in resolver.nameservers:
                if server not in self.trusted_ips:
                    self.trusted_ips.add(server)
                    logging.info(f"[*] Legitimate DNS server added from system configuration: {server}")
        except Exception as e:
            logging.error(f"Error discovering system DNS: {e}")

    def discover_network_devices(self):
        """Performs a passive and active scan to discover network devices and adds them to the trusted list."""
        with self.ui_lock:
            self.console.log(f"[bold cyan]Discovering devices on the network...[/bold cyan]")
        
        if self.gateway_ip_v4:
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{self.gateway_ip_v4}/24"), timeout=2, iface=self.interface, verbose=False)
                for _, received in ans:
                    ip = received[ARP].psrc
                    mac = received[Ether].src
                    if ip not in self.trusted_ips:
                        self.trusted_ips.add(ip)
                        logging.info(f"[*] Legitimate device discovered and added to trusted IPs: {ip} -> {mac}")
            except Exception as e:
                logging.error(f"Error scanning IPv4: {e}")
        
        try:
            ans, _ = srp(Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_RA(), timeout=2, iface=self.interface, verbose=False)
            for _, received in ans:
                router_ip = received[IPv6].src
                router_mac = received[Ether].src
                if router_ip not in self.trusted_ips:
                    self.trusted_ips.add(router_ip)
                    self.gateway_ip_v6 = router_ip
                    self.gateway_mac_v6 = router_mac
                    logging.info(f"[*] Legitimate IPv6 router discovered and added to trusted IPs: {router_ip} -> {router_mac}")

            ans, _ = srp(Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_NS(), timeout=2, iface=self.interface, verbose=False)
            for _, received in ans:
                ip = received[IPv6].src
                mac = received[Ether].src
                if ip not in self.trusted_ips and ip != self.my_ipv6_local and ip != self.gateway_ip_v6:
                    self.trusted_ips.add(ip)
                    logging.info(f"[*] Legitimate IPv6 device discovered and added to trusted IPs: {ip} -> {mac}")
        except Exception as e:
            logging.error(f"Error scanning IPv6: {e}")
        
        self.discover_system_dns()
        with self.ui_lock:
            self.console.log(f"[bold green]Network discovery complete. Starting monitoring...[/bold green]")

    def run_periodic_scans(self):
        """Runs network scans every 5 minutes to keep the trusted table updated."""
        while self.active and not self.passive_mode and not self.test_mode:
            time.sleep(300)
            self.discover_network_devices()

    def run_active_countermeasures(self):
        """Sends gratuitous ARP and ND packets to reset the network tables."""
        while self.active:
            if not self.passive_mode and not self.test_mode:
                try:
                    if self.gateway_ip_v4 and self.gateway_mac_v4:
                        arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=self.gateway_ip_v4, hwsrc=self.gateway_mac_v4, pdst=self.my_ip)
                        sendp(arp_packet, iface=self.interface, verbose=False)
                        logging.info(f"[+] Sending ARP countermeasures. Router: {self.gateway_ip_v4} has MAC: {self.gateway_mac_v4}")
                    
                    if self.gateway_ip_v6 and self.gateway_mac_v6:
                        nd_packet = Ether(dst=self.gateway_mac_v6) / IPv6(src=self.gateway_ip_v6, dst="ff02::1") / ICMPv6ND_NA(tgt=self.gateway_ip_v6, S=1, R=1, O=1)
                        sendp(nd_packet, iface=self.interface, verbose=False)
                        logging.info(f"[+] Sending ND countermeasures. IPv6 Router: {self.gateway_ip_v6} has MAC: {self.gateway_mac_v6}")

                except Exception as e:
                    logging.error(f"Error sending countermeasures: {e}")
            
            time.sleep(3)

    def monitor_arp_cache(self):
        """
        Proactively checks the system's ARP cache to detect
        poisoning even without receiving packets.
        """
        while self.active:
            if not self.test_mode and self.gateway_ip_v4 and self.gateway_mac_v4:
                try:
                    current_gateway_mac = getmacbyip(self.gateway_ip_v4)
                    if current_gateway_mac and current_gateway_mac != self.gateway_mac_v4:
                        self.log_alert(
                            "PROACTIVE_ARP_SPOOFING",
                            f"The router's MAC in the system's ARP cache has changed unexpectedly.",
                            f"Original MAC: {self.gateway_mac_v4}, Suspicious MAC: {current_gateway_mac}",
                            packet=None 
                        )
                except Exception as e:
                    logging.error(f"Error monitoring ARP cache: {e}")
            time.sleep(10)
    
    def test_dns_spoofing(self):
        """Creates a list of test packets and processes them to simulate the attack."""
        with self.ui_lock:
            self.console.log(f"[*] [bold cyan]Starting DNS Spoofing attack simulation...[/bold cyan]")
        
        if not self.my_ip or not self.gateway_ip_v4:
            with self.ui_lock:
                 self.console.log("Could not get IP and/or gateway. Cannot run DNS Spoofing test.")
            return

        test_domain = "test.com"
        test_ip = "1.2.3.4"
        
        test_packets = []
        
        # Legitimate DNS query packet
        dns_query_packet = (
            Ether(src=self.my_mac, dst=self.gateway_mac_v4) /
            IP(src=self.my_ip, dst=self.gateway_ip_v4) /
            UDP(sport=55555, dport=53) /
            DNS(id=1234, qr=0, rd=1, qd=DNSQR(qname=test_domain, qtype="A"))
        )
        
        # Malicious DNS response packet
        dns_spoofed_packet = (
            Ether(src=self.gateway_mac_v4, dst=self.my_mac) /
            IP(src=self.gateway_ip_v4, dst=self.my_ip) /
            UDP(sport=53, dport=55555) /
            DNS(id=1234, qr=1, aa=1, rd=1, ra=1, 
                qd=DNSQR(qname=test_domain, qtype="A"), 
                an=DNSRR(rrname=test_domain, ttl=600, rdata=test_ip))
        )
        
        test_packets.append(dns_query_packet)
        test_packets.append(dns_spoofed_packet)
        
        with self.ui_lock:
            self.console.log("[*] Processing test packets...")
        for pkt in test_packets:
            self.handle_packet(pkt)
            
        with self.ui_lock:
            self.console.log(f"[*] [bold green]Attack test finished. Verifying result...[/bold green]")
        self.stop()

    def handle_arp(self, packet):
        """Handles ARP packets to detect and mitigate spoofing."""
        if not self.active:
            return
            
        try:
            arp_op = packet[ARP].op
            arp_src_ip = packet[ARP].psrc
            arp_src_mac = packet[ARP].hwsrc

            if arp_op == 2:
                if self.gateway_ip_v4 and arp_src_ip == self.gateway_ip_v4 and arp_src_mac != self.gateway_mac_v4:
                    self.log_alert(
                        "ARP_SPOOFING",
                        f"IP {arp_src_ip} has changed MAC address.",
                        f"Original MAC: {self.gateway_mac_v4}, Suspicious MAC: {arp_src_mac}",
                        packet=packet
                    )
                
            if arp_src_ip not in self.arp_table or self.arp_table[arp_src_ip] != arp_src_mac:
                with self.ui_lock:
                    self.arp_table[arp_src_ip] = arp_src_mac
                    self.console.log(f"New ARP entry: IP {arp_src_ip} -> MAC {arp_src_mac}")
        
        except IndexError:
            pass

    def handle_ipv6_nd(self, packet):
        """Handles ICMPv6 ND packets to detect spoofing in IPv6."""
        if not self.active:
            return
        
        try:
            if packet.haslayer(ICMPv6ND_NA):
                target_ip = packet[IPv6].src
                target_mac = packet[Ether].src
                if target_ip not in self.trusted_ips:
                    self.trusted_ips.add(target_ip)
                    logging.info(f"[*] Legitimate IPv6 device discovered and added to trusted IPs: {target_ip} -> {target_mac}")
                
            if packet.haslayer(ICMPv6ND_RA):
                router_ip = packet[IPv6].src
                if router_ip not in self.trusted_ips:
                    self.trusted_ips.add(router_ip)
                    logging.info(f"[*] IPv6 Gateway discovered and added to trusted IPs: {router_ip}")
                    self.gateway_ip_v6 = router_ip
                    self.gateway_mac_v6 = packet[Ether].src
            
            if packet.haslayer(ICMPv6ND_NA) or packet.haslayer(ICMPv6ND_NS):
                target_ip = packet[IPv6].src
                target_mac = packet[Ether].src
                
                if self.gateway_ip_v6 and target_ip == self.gateway_ip_v6 and target_mac != self.gateway_mac_v6:
                     self.log_alert(
                         "ICMPv6_SPOOFING",
                         f"IPv6 IP {target_ip} has changed MAC address.",
                         f"Original MAC: {self.gateway_mac_v6}, Suspicious MAC: {target_mac}",
                         packet=packet
                     )
                
                if target_ip not in self.neighbor_table or self.neighbor_table[target_ip] != target_mac:
                    with self.ui_lock:
                        self.neighbor_table[target_ip] = target_mac
                        self.console.log(f"New IPv6 ND entry: IP {target_ip} -> MAC {target_mac}")
        except IndexError:
            pass

    def check_dns_query(self, packet):
        """Stores DNS queries to check responses later."""
        if not self.active:
            return
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                query_id = packet[DNS].id
                query_name = packet[DNS][DNSQR].qname
                self.dns_queries[query_id] = query_name
        except IndexError:
            pass

    def check_dns_response(self, packet):
        """Verifies if DNS responses are legitimate or spoofed."""
        if not self.active:
            return
        
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 1:
                response_src_ip = None
                if packet.haslayer(IP):
                    response_src_ip = packet[IP].src
                elif packet.haslayer(IPv6):
                    response_src_ip = packet[IPv6].src
                
                if response_src_ip and response_src_ip.startswith("fe80::"):
                    if packet[DNS].id in self.dns_queries:
                        del self.dns_queries[packet[DNS].id]
                    return

                if packet.haslayer(DNS) and packet[DNS].id in self.dns_queries:
                    query_name_raw = self.dns_queries[packet[DNS].id]
                    query_name = query_name_raw.decode('utf-8').strip('.')

                    packet_resolved_ips = []
                    if isinstance(packet[DNS].ancount, int) and packet[DNS].ancount > 0:
                        for i in range(packet[DNS].ancount):
                            if packet[DNS].an and len(packet[DNS].an) > i and packet[DNS].an[i].type == 1 and hasattr(packet[DNS].an[i], 'rdata'):
                                packet_resolved_ips.append(packet[DNS].an[i].rdata)
                    
                    if query_name.endswith('.local'):
                        with self.ui_lock:
                            self.console.log(f"[*] Ignoring local query: {query_name}")
                        if packet[DNS].id in self.dns_queries:
                             del self.dns_queries[packet[DNS].id]
                        return

                    if not packet_resolved_ips:
                        self.log_alert(
                            "DNS_EMPTY_RESPONSE",
                            f"Empty DNS response for '{query_name}'.",
                            "Possible capture error, not considered an attack."
                        )
                        if packet[DNS].id in self.dns_queries:
                            del self.dns_queries[packet[DNS].id]
                        return

                    trusted_dns_servers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
                    valid_ips = []
                    for server in trusted_dns_servers:
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.nameservers = [server]
                            resolved_addresses = [str(rdata.address) for rdata in resolver.resolve(query_name, 'A', lifetime=2)]
                            valid_ips.extend(resolved_addresses)
                        except (dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                            pass

                    is_spoofed = False
                    if not any(ip in valid_ips for ip in packet_resolved_ips):
                        is_spoofed = True
                    
                    if is_spoofed:
                        expected_ips_str = ', '.join(set(valid_ips)) if valid_ips else "No legitimate IPs"
                        
                        self.log_alert(
                            "DNS_SPOOFING",
                            f"DNS response for '{query_name}' is invalid.",
                            f"Expected IPs: {expected_ips_str}, Received IPs: {packet_resolved_ips}",
                            packet=packet
                        )
                    
                    if packet[DNS].id in self.dns_queries:
                        del self.dns_queries[packet[DNS].id]

        except IndexError:
            pass
        except Exception as e:
            logging.error(f"Error in check_dns_response: {e}")

    def check_for_sslstrip(self, packet):
        """Checks for HTTP requests to sites that should be HTTPS."""
        if not self.active:
            return
        
        try:
            if packet.haslayer(HTTPRequest) and packet.haslayer(IP):
                host = packet[HTTPRequest].Host.decode('utf-8')
                dest_ip = packet[IP].dst
                
                if any(domain in host for domain in self.secure_domains):
                    if host in self.dns_responses and dest_ip in self.dns_responses[host]:
                        self.log_alert(
                            "SSLSTRIP",
                            f"Detected an insecure HTTP connection to a sensitive website.",
                            f"Domain: {host}, Destination IP: {dest_ip}. This could be an SSLstrip attack.",
                            packet=packet
                        )
                    if host in self.dns_responses:
                        del self.dns_responses[host]
        except IndexError:
            pass
        except Exception as e:
            logging.error(f"Error in check_for_sslstrip: {e}")

    def handle_dhcp_packet(self, packet):
        if not self.active:
            return

        try:
            if packet.haslayer(DHCP) and packet[DHCP].options and packet[DHCP].options[0] and packet[DHCP].options[0][1] == 2:
                src_ip = packet[IP].src
                if src_ip != self.gateway_ip_v4 and src_ip not in self.trusted_ips:
                    self.log_alert(
                        "DHCP_SPOOFING",
                        f"Unauthorized DHCP server detected.",
                        f"Suspicious server IP: {src_ip}, MAC: {packet[Ether].src}",
                        packet=packet
                    )
        except IndexError:
            pass
        except Exception as e:
            logging.error(f"Error in handle_dhcp_packet: {e}")
            
    def handle_packet(self, packet):
        """Main function to handle all packets."""
        with self.ui_lock:
            self.packet_count += 1
        
        try:
            if packet.haslayer(ARP):
                self.handle_arp(packet)
            if packet.haslayer(ICMPv6ND_RA) or packet.haslayer(ICMPv6ND_NA) or packet.haslayer(ICMPv6ND_NS):
                self.handle_ipv6_nd(packet)
            if packet.haslayer(DNS):
                self.check_dns_query(packet)
                self.check_dns_response(packet)
            if packet.haslayer(HTTPRequest):
                self.check_for_sslstrip(packet)
            if packet.haslayer(DHCP):
                self.handle_dhcp_packet(packet)
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def generate_layout(self):
        """Generates the UI layout for Rich."""
        with self.ui_lock:
            status_panel = Panel(
                f"[bold white]Status:[/] [bold green]Active[/]\n"
                f"[bold white]Interface:[/] {self.interface}\n"
                f"[bold white]IPv4 Gateway:[/] {self.gateway_ip_v4} ({self.gateway_mac_v4})\n"
                f"[bold white]Packets processed:[/] {self.packet_count}",
                title="Detection Status"
            )

            trusted_devices_table = Table(title="Network Devices")
            trusted_devices_table.add_column("IP", style="cyan")
            trusted_devices_table.add_column("MAC", style="magenta")
            
            for ip, mac in self.arp_table.items():
                trusted_devices_table.add_row(ip, mac)
            for ip, mac in self.neighbor_table.items():
                trusted_devices_table.add_row(ip, mac)

            alerts_panel_content = ""
            for timestamp, alert in self.alerts:
                alerts_panel_content += f"[bold red]{timestamp}[/] - [bold yellow]{alert}[/]\n"
            
            alerts_panel = Panel(Text(alerts_panel_content, justify="left"), title="Security Alerts")

            panels = [status_panel, trusted_devices_table, alerts_panel]

            if self.recent_malicious_packet:
                packet_io = io.StringIO()
                original_stdout = sys.stdout
                sys.stdout = packet_io
                
                self.recent_malicious_packet.show()
                
                sys.stdout = original_stdout
                
                packet_dump = packet_io.getvalue()
                
                syntax = Syntax(packet_dump, "python", theme="monokai", line_numbers=False)
                packet_panel = Panel(syntax, title="Malicious Packet Details")
                panels.append(packet_panel)

        return Columns(panels)

    def start_ui(self):
        """Starts the interactive UI thread."""
        with Live(self.generate_layout(), screen=True, auto_refresh=True, vertical_overflow="visible") as live:
            while self.active:
                live.update(self.generate_layout())
                time.sleep(0.5)
            if self.test_mode:
                time.sleep(2)

    def start_passive_detection(self):
        """Starts the sniffer in passive mode."""
        try:
            sniff(prn=self.handle_packet, iface=self.interface, store=0)
        except Exception as e:
            logging.error(f"Error starting sniffer: {e}")
            self.stop()
            
    def run(self):
        """Runs the detection tool."""
        self.discover_network_devices()

        if self.test_mode:
            self.test_dns_spoofing()
        else:
            sniffer_thread = threading.Thread(target=self.start_passive_detection, daemon=True)
            sniffer_thread.start()
            
            arp_monitor_thread = threading.Thread(target=self.monitor_arp_cache, daemon=True)
            arp_monitor_thread.start()
            
            scan_thread = threading.Thread(target=self.run_periodic_scans, daemon=True)
            scan_thread.start()
            
            if self.countermeasures and not self.passive_mode:
                countermeasure_thread = threading.Thread(target=self.run_active_countermeasures, daemon=True)
                countermeasure_thread.start()

            self.start_ui()

    def stop(self):
        self.active = False
        sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Tool for detecting and mitigating MitM attacks on IPv4 and IPv6.")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to monitor (e.g., eth0, Wi-Fi).")
    parser.add_argument('-c', '--countermeasures', action='store_true', help="Activates active countermeasures to mitigate the attack.")
    parser.add_argument('-p', '--passive', action='store_true', help="Runs the script in passive mode (detection only, no mitigation).")
    parser.add_argument('--trusted-ips', type=str, help="List of trusted IPs, separated by commas. (e.g., 192.168.1.39)")
    parser.add_argument('-t', '--test', action='store_true', help="Activates test mode to simulate a DNS Spoofing attack locally.")
    args = parser.parse_args()
    
    trusted_ips_list = args.trusted_ips.split(',') if args.trusted_ips else []
    
    detector = MitMDetection(
        interface=args.interface,
        countermeasures=args.countermeasures,
        passive_mode=args.passive,
        trusted_ips=trusted_ips_list,
        test_mode=args.test
    )
    detector.run()
