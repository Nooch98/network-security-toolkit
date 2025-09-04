from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
import io
import socket
import keyboard
import requests
from typing import Dict, List, Optional, Set, Tuple, Union

from colorama import init as colorama_init
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.syntax import Syntax

# scapy
from scapy.all import (
    ARP,
    Ether,
    IPv6,
    IP,
    sniff,
    sendp,
    get_if_addr,
    get_if_hwaddr,
    conf,
    srp,
    wrpcap,
    Raw
)
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import getmacbyip
from scapy.layers.http import HTTPRequest
from scapy.layers.dhcp import DHCP
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6ND_NS

import dns.resolver

try:
    import networkx as nx
    import matplotlib.pyplot as plt
    DIAGRAM_LIBS_INSTALLED = True
except ImportError:
    DIAGRAM_LIBS_INSTALLED = False

# Inicializar colorama
colorama_init(autoreset=True)

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    3389: "RDP"
}


class DNSCache:
    """Caché simple para consultas A usando resolvers especificados."""

    def __init__(self, resolvers: List[str], ttl_default: int = 300, timeout: float = 2.0):
        self.resolvers = resolvers
        self.ttl_default = ttl_default
        self.timeout = timeout
        self.cache: Dict[str, Tuple[Set[str], float, int]] = {}
        self._resolver_objs: List[dns.resolver.Resolver] = []
        for s in self.resolvers:
            r = dns.resolver.Resolver(configure=False)
            r.lifetime = self.timeout
            r.nameservers = [s]
            self._resolver_objs.append(r)

    def resolve_a(self, name: str) -> Set[str]:
        now = time.time()
        key = name.lower().rstrip('.')
        entry = self.cache.get(key)
        if entry:
            ips, ts, ttl = entry
            if now - ts < ttl:
                return set(ips)

        ips: Set[str] = set()
        for r in self._resolver_objs:
            try:
                ans = r.resolve(key, 'A')
                for rr in ans:
                    try:
                        ips.add(str(rr.address))
                    except Exception:
                        pass
                try:
                    ttl = min([getattr(rr, 'ttl', self.ttl_default) for rr in ans])
                except Exception:
                    ttl = self.ttl_default
                self.cache[key] = (ips, now, int(ttl) if ips else self.ttl_default)
                if ips:
                    return ips
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                self.cache[key] = (set(), now, 60)
                return set()
            except (dns.resolver.Timeout, dns.exception.DNSException):
                continue

        self.cache[key] = (set(), now, 30)
        return set()


class MitMDetection:
    def __init__(
        self,
        interface: str,
        trusted_ips: Optional[List[str]] = None,
        countermeasures: bool = False,
        passive_mode: bool = False,
        test_mode: bool = False,
        json_out: Optional[str] = None,
        active_scan: bool = True,
        log_only: bool = False,
        log_level: str = 'INFO',
    ):
        self.interface = interface
        self.trusted_ips: Set[str] = set(trusted_ips or [])
        self.countermeasures = countermeasures
        self.passive_mode = passive_mode
        self.test_mode = test_mode
        self.active = True
        self.stop_event = threading.Event()
        self.json_out = json_out
        self.active_scan = active_scan
        self.log_only = log_only
        self.network_map: Dict[str, Dict[str, Union[str, bool, None]]] = {}
        self.open_ports: Dict[str, Set[int]] = {}
        self.image_path: Optional[str] = None

        self.console = Console()
        self.alerts: List[Tuple[str, str]] = []
        self.packet_count = 0
        self.ui_lock = threading.Lock()
        self.recent_malicious_packet = None
        self._devices_per_page = 10
        self._page_index = 0
        self.device_fp: Dict[str, Dict[str, Union[Set[str], int]]] = {}
        self._gateway_candidates = {}
        self._observed_routers = set()
        self.tcp_requests: List[Dict] = []
        self.max_tcp_requests = 10
        self.oui_database = {}
        self._load_local_oui_database()
        self.get_manufacturer_by_mac = self.get_manufacturer_by_mac
        self.unusual_dns_queries: List[Tuple[str, str, str]] = []

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

        self.arp_table: Dict[str, str] = {}
        self.neighbor_table: Dict[str, str] = {}
        self.dns_queries: Dict[int, bytes] = {}
        self.dns_responses: Dict[str, Set[str]] = {}

        if self.my_ip:
            self.trusted_ips.add(self.my_ip)
        if self.my_ipv6_local:
            self.trusted_ips.add(self.my_ipv6_local)
        if self.gateway_ip_v4:
            self.trusted_ips.add(self.gateway_ip_v4)

        self.secure_domains = [
            "google.com",
            "facebook.com",
            "github.com",
            "microsoft.com",
            "amazon.com",
        ]

        self.dns_cache = DNSCache(["8.8.8.8", "1.1.1.1", "9.9.9.9"], ttl_default=300, timeout=2.0)

        self._setup_logging(log_level)

    # -------------------- setup --------------------
    def _get_local_ipv6_for_interface(self) -> Optional[str]:
        try:
            from scapy.all import get_if_addr6
            ipv6_info = get_if_addr6(self.interface)
            if ipv6_info and "addr" in ipv6_info:
                return ipv6_info["addr"]
        except Exception:
            pass
        return None

    def _setup_logging(self, level: str):
        lvl = getattr(logging, (level or 'INFO').upper(), logging.INFO)
        logging.basicConfig(
            level=lvl,
            format='%(message)s',
            datefmt='[%X]',
            handlers=[
                logging.FileHandler('mitm_detector.log', mode='a'),
            ],
        )

    # -------------------- logging & alerts --------------------
    def _write_json_event(self, payload: dict):
        if not self.json_out:
            return
        try:
            with open(self.json_out, 'a', encoding='utf-8') as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as e:
            logging.error(f"Error escribiendo evento JSON: {e}")

    def log_malicious_packet(self, packet, alert_type: str):
        try:
            filename = f"{alert_type.lower()}_alerts.pcap"
            wrpcap(filename, packet, append=True)
            logging.critical(f"[*] Paquete malicioso guardado en '{filename}'.")
        except Exception as e:
            logging.error(f"Error guardando pcap: {e}")

    def log_alert(self, alert_type: str, message: str, details: str, packet=None):
        ts = time.strftime("%H:%M:%S")
        alert_text = f"[{alert_type}] {message} -> {details}"
        with self.ui_lock:
            self.alerts.insert(0, (ts, alert_text))
            self.alerts = self.alerts[:10]
        logging.critical(f"ALERTA: {alert_type} - {message} -> {details}")

        self._write_json_event({
            'time': int(time.time()),
            'alert_type': alert_type,
            'message': message,
            'details': details,
        })

        if packet is not None:
            self.log_malicious_packet(packet, alert_type)
            self.recent_malicious_packet = packet

    # -------------------- descubrimiento --------------------
    def _update_fingerprint(self, ip: str, packet):
        fp = self.device_fp.setdefault(ip, {'ttls': set(), 'tcp_windows': set(), 'http_ua': set(), 'dhcp_client_ids': set()})
        try:
            if packet.haslayer(IP):
                ttl = packet[IP].ttl
                fp['ttls'].add(int(ttl))
            # TCP window size
            if packet.haslayer('TCP'):
                win = packet['TCP'].window
                fp['tcp_windows'].add(int(win))
            # HTTP User-Agent
            if packet.haslayer(HTTPRequest):
                ua = packet[HTTPRequest].User_Agent.decode('utf-8', errors='ignore') if getattr(packet[HTTPRequest], 'User_Agent', None) else None
                if ua:
                    fp['http_ua'].add(ua)
            # DHCP client-id
            if packet.haslayer(DHCP):
                opts = packet[DHCP].options
                for opt in opts:
                    if isinstance(opt, tuple) and opt[0] == 'client_id':
                        fp['dhcp_client_ids'].add(str(opt[1]))
        except Exception:
            pass
        
    def fingerprint_changed(self, ip: str) -> bool:
        fp = self.device_fp.get(ip)
        if not fp:
            return False
        if len(fp['ttls']) > 2:
            self.log_alert("FP_CHANGE", f"TTL variable para {ip}", f"TTLs observados: {sorted(fp['ttls'])}")
            return True
        return False
    
    def _note_router(self, ip: str, mac: str):
        s = self._gateway_candidates.setdefault(ip, set())
        s.add(mac)
        
        if len(s) > 1:
            self.log_alert("MULTI_GATEWAY", f"Multiples MACs para gateway {ip}", f"MACs: {sorted(list(s))}")
            
    def _note_observed_router(self, ip: str):
        self._observed_routers.add(ip)
        if len(self._observed_routers) > 1:
            self.log_alert("ROGUE_ROUTER", "Se han observado multiples routers en la red", f"Routers: {sorted(list(self._observed_routers))}")
    
    def discover_system_dns(self):
        try:
            resolver = dns.resolver.Resolver()
            for server in resolver.nameservers:
                if server not in self.trusted_ips:
                    self.trusted_ips.add(server)
                    logging.info(f"[*] DNS del sistema añadido como confiable: {server}")
        except Exception as e:
            logging.debug(f"Error descubriendo DNS: {e}")

    def discover_network_devices_ipv4(self):
        if not self.gateway_ip_v4:
            return
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{self.gateway_ip_v4}/24"), timeout=2, iface=self.interface, verbose=False)
            for _, received in ans:
                ip = received[ARP].psrc
                mac = received[Ether].src
                if ip not in self.trusted_ips:
                    self.trusted_ips.add(ip)
                    logging.info(f"[*] Dispositivo IPv4 descubierto: {ip} -> {mac}")
        except Exception as e:
            logging.debug(f"Error escaneo IPv4: {e}")

    def discover_network_devices_ipv6(self):
        try:
            ans, _ = srp(Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_RA(), timeout=2, iface=self.interface, verbose=False)
            for _, received in ans:
                router_ip = received[IPv6].src
                router_mac = received[Ether].src
                if router_ip not in self.trusted_ips:
                    self.trusted_ips.add(router_ip)
                    self.gateway_ip_v6 = router_ip
                    self.gateway_mac_v6 = router_mac
                    logging.info(f"[*] Router IPv6 descubierto: {router_ip} -> {router_mac}")

            ans, _ = srp(Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_NS(), timeout=2, iface=self.interface, verbose=False)
            for _, received in ans:
                ip = received[IPv6].src
                mac = received[Ether].src
                if ip not in self.trusted_ips and ip != self.my_ipv6_local and ip != self.gateway_ip_v6:
                    self.trusted_ips.add(ip)
                    logging.info(f"[*] Dispositivo IPv6 descubierto: {ip} -> {mac}")
        except Exception as e:
            logging.debug(f"Error escaneo IPv6: {e}")

    def discover_network_devices(self):
        with self.ui_lock:
            self.network_map = {}
            self.open_ports = {}
        if self.active_scan:
            self.discover_network_devices_ipv4()
            self.discover_network_devices_ipv6()
        self.discover_system_dns()
        
    def run_periodic_scans(self):
        while self.active and not self.passive_mode and not self.test_mode and not self.stop_event.is_set():
            if self.stop_event.wait(300):
                break
            self.discover_network_devices()

    # -------------------- contramedidas --------------------
    def run_active_countermeasures(self):
        while self.active and not self.stop_event.is_set():
            if not self.passive_mode and not self.test_mode:
                try:
                    if self.gateway_ip_v4 and self.gateway_mac_v4 and self.my_ip:
                        arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=self.gateway_ip_v4, hwsrc=self.gateway_mac_v4, pdst=self.my_ip)
                        sendp(arp_packet, iface=self.interface, verbose=False)

                    if self.gateway_ip_v6 and self.gateway_mac_v6:
                        nd_packet = Ether(dst=self.gateway_mac_v6) / IPv6(src=self.gateway_ip_v6, dst="ff02::1") / ICMPv6ND_NA(tgt=self.gateway_ip_v6, S=1, R=1, O=1)
                        sendp(nd_packet, iface=self.interface, verbose=False)
                except Exception as e:
                    logging.debug(f"Error contramedidas: {e}")
            if self.stop_event.wait(3):
                break

    # -------------------- monitoreo --------------------
    def monitor_arp_cache(self):
        while self.active and not self.stop_event.is_set():
            if not self.test_mode and self.gateway_ip_v4 and self.gateway_mac_v4:
                try:
                    current_gateway_mac = getmacbyip(self.gateway_ip_v4)
                    if current_gateway_mac and current_gateway_mac != self.gateway_mac_v4:
                        self.log_alert(
                            "ARP_SPOOFING_PROACTIVO",
                            "La MAC del router en la caché ARP cambió inesperadamente",
                            f"Original: {self.gateway_mac_v4}, Sospechosa: {current_gateway_mac}",
                            packet=None,
                        )
                except Exception as e:
                    logging.debug(f"Error monitoreando caché ARP: {e}")
            if self.stop_event.wait(10):
                break
    
    def _port_scan_worker(self):
        while self.active and not self.stop_event.is_set():
            if self.network_map:
                for ip in self.network_map:
                    if ip not in self.open_ports:
                        with self.ui_lock:
                            self.open_ports[ip] = set()
                        self._scan_ports(ip)
            if self.stop_event.wait(30):
                break

    def _scan_ports(self, ip: str):
        ports_to_scan = [22, 25, 80, 139, 443, 445, 3389, 8080]
        for port in ports_to_scan:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    with self.ui_lock:
                        self.open_ports[ip].add(port)
            except Exception as e:
                logging.debug(f"Error en escaneo de puerto {ip}:{port}: {e}")
            finally:
                sock.close()


    # -------------------- test mode --------------------
    def test_dns_spoofing(self):
        logging.info("[*] Iniciando simulación de DNS Spoofing...")
        if not self.my_ip or not self.gateway_ip_v4 or not self.my_mac or not self.gateway_mac_v4:
            logging.warning("No se pudo obtener IP/MAC o gateway. No se puede ejecutar la prueba.")
            return
        test_domain = "test.com"
        test_ip = "1.2.3.4"
        dns_query_packet = Ether(src=self.my_mac, dst=self.gateway_mac_v4)/IP(src=self.my_ip, dst=self.gateway_ip_v4)/UDP(sport=55555, dport=53)/DNS(id=1234, qr=0, rd=1, qd=DNSQR(qname=test_domain, qtype="A"))
        dns_spoofed_packet = Ether(src=self.gateway_mac_v4, dst=self.my_mac)/IP(src=self.gateway_ip_v4, dst=self.my_ip)/UDP(sport=53, dport=55555)/DNS(id=1234, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=test_domain, qtype="A"), an=DNSRR(rrname=test_domain, ttl=600, rdata=test_ip))
        for pkt in (dns_query_packet, dns_spoofed_packet):
            self.handle_packet(pkt)
        logging.info("[*] Prueba finalizada.")
        self.stop()

    # -------------------- manejadores --------------------
    def handle_arp(self, packet):
        try:
            arp_op = packet[ARP].op
            arp_src_ip = packet[ARP].psrc
            arp_src_mac = packet[ARP].hwsrc

            # Comprobación de ARP Spoofing
            if arp_op == 2:
                if self.gateway_ip_v4 and arp_src_ip == self.gateway_ip_v4 and self.gateway_mac_v4 and arp_src_mac != self.gateway_mac_v4:
                    self.log_alert(
                        "ARP_SPOOFING",
                        f"La IP {arp_src_ip} cambió de MAC",
                        f"Original: {self.gateway_mac_v4}, Sospechosa: {arp_src_mac}",
                        packet=packet,
                    )

            if arp_src_ip not in self.arp_table or self.arp_table[arp_src_ip] != arp_src_mac:
                with self.ui_lock:
                    self.arp_table[arp_src_ip] = arp_src_mac
                    
                    os_type = self.get_os_from_ttl(packet[IP].ttl) if packet.haslayer(IP) else 'N/A'
                    manufacturer = self.get_manufacturer_by_mac(arp_src_mac)
                    
                    self.network_map[arp_src_ip] = {
                        'mac': arp_src_mac,
                        'is_router': (arp_src_ip == self.gateway_ip_v4),
                        'os_type': os_type,
                        'manufacturer': manufacturer
                    }
        except Exception:
            pass

    def handle_ipv6_nd(self, packet):
        try:
            if packet.haslayer(ICMPv6ND_NA):
                target_ip = packet[IPv6].src
                target_mac = packet[Ether].src
                if target_ip not in self.trusted_ips:
                    self.trusted_ips.add(target_ip)
                    self.network_map[target_ip] = {'mac': target_mac, 'is_router': (target_ip == self.gateway_ip_v6)}
            if packet.haslayer(ICMPv6ND_RA):
                router_ip = packet[IPv6].src
                router_mac = packet[Ether].src
                if router_ip not in self.trusted_ips:
                    self.trusted_ips.add(router_ip)
                    self.gateway_ip_v6 = router_ip
                    self.gateway_mac_v6 = router_mac
                    self.network_map[router_ip] = {'mac': self.gateway_mac_v6, 'is_router': True}
            if packet.haslayer(ICMPv6ND_NA) or packet.haslayer(ICMPv6ND_NS):
                target_ip = packet[IPv6].src
                target_mac = packet[Ether].src
                if self.gateway_ip_v6 and target_ip == self.gateway_ip_v6 and self.gateway_mac_v6 and target_mac != self.gateway_mac_v6:
                    self.log_alert(
                        "ICMPv6_SPOOFING",
                        f"IPv6 {target_ip} cambió de MAC",
                        f"Original: {self.gateway_mac_v6}, Sospechosa: {target_mac}",
                        packet=packet,
                    )
                if target_ip not in self.neighbor_table or self.neighbor_table[target_ip] != target_mac:
                    with self.ui_lock:
                        self.neighbor_table[target_ip] = target_mac
                        self.network_map[target_ip] = {'mac': target_mac, 'is_router': (target_ip == self.gateway_ip_v6)}
        except Exception:
            pass

    def check_dns_query(self, packet):
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                self.dns_queries[packet[DNS].id] = packet[DNS][DNSQR].qname

            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                dns_query = packet.getlayer(DNS).qd.qname.decode('utf-8')
                src_ip = packet.getlayer(IP).src
                
                is_unusual = False
                unusual_reason = ""

                parts = dns_query.split('.')
                if len(parts[0]) > 30:
                    is_unusual = True
                    unusual_reason = f"Subdominio inusualmente largo ({len(parts[0])} caracteres)"

                if not is_unusual:
                    tld = parts[-2] if len(parts) > 1 else ""
                    if tld in ["ru", "bit", "cc", "ga", "ml", "tk"]:
                        is_unusual = True
                        unusual_reason = f"TLD sospechoso: .{tld}"

                if is_unusual:
                    with self.ui_lock:
                        self.unusual_dns_queries.append((time.strftime("%H:%M:%S"), src_ip, dns_query))
                        if len(self.unusual_dns_queries) > 20:
                            self.unusual_dns_queries.pop(0)

        except Exception as e:
            logging.debug(f"Error procesando paquete DNS: {e}")

    def check_dns_response(self, packet):
        try:
            if not (packet.haslayer(DNS) and packet[DNS].qr == 1):
                return
            response_src_ip = None
            if packet.haslayer(IP):
                response_src_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                response_src_ip = packet[IPv6].src
            if response_src_ip and str(response_src_ip).startswith("fe80::"):
                self.dns_queries.pop(packet[DNS].id, None)
                return
            if packet[DNS].id not in self.dns_queries:
                return
            query_name_raw = self.dns_queries.pop(packet[DNS].id, b"")
            try:
                query_name = query_name_raw.decode('utf-8').strip('.')
            except Exception:
                query_name = str(query_name_raw).strip('.')
            if query_name.endswith('.local'):
                return
            packet_resolved_ips: List[str] = []
            ancount = int(getattr(packet[DNS], 'ancount', 0) or 0)
            if ancount > 0 and getattr(packet[DNS], 'an', None):
                ans = packet[DNS].an
                for _ in range(ancount):
                    if getattr(ans, 'type', None) == 1 and hasattr(ans, 'rdata'):
                        packet_resolved_ips.append(str(ans.rdata))
                    ans = getattr(ans, 'payload', None)
                    if ans is None:
                        break
            if not packet_resolved_ips:
                self.log_alert("DNS_RESPUESTA_VACIA", f"Respuesta DNS vacía para '{query_name}'", "Posible error de captura; no es un ataque")
                return
            valid_ips = self.dns_cache.resolve_a(query_name)
            is_spoofed = bool(valid_ips) and not any(ip in valid_ips for ip in packet_resolved_ips)
            if is_spoofed:
                self.log_alert(
                    "DNS_SPOOFING",
                    f"Respuesta DNS inválida para '{query_name}'",
                    f"Se esperaba: {sorted(valid_ips)}; Recibido: {packet_resolved_ips}",
                    packet=packet,
                )
            self.dns_responses[query_name] = set(packet_resolved_ips)
        except Exception as e:
            logging.debug(f"Error comprobando respuesta DNS: {e}")

    def check_for_sslstrip(self, packet):
        try:
            if not (packet.haslayer(HTTPRequest) and packet.haslayer(IP)):
                return
            host = packet[HTTPRequest].Host.decode('utf-8') if packet[HTTPRequest].Host else ''
            dest_ip = packet[IP].dst
            if any(domain in host for domain in self.secure_domains):
                if host in self.dns_responses and str(dest_ip) in self.dns_responses.get(host, set()):
                    self.log_alert(
                        "SSLSTRIP",
                        "Conexión HTTP insegura a sitio sensible",
                        f"Dominio: {host}, IP destino: {dest_ip}",
                        packet=packet,
                    )
                self.dns_responses.pop(host, None)
        except Exception:
            pass

    def handle_dhcp_packet(self, packet):
        try:
            if packet.haslayer(DHCP) and packet[DHCP].options:
                opts = packet[DHCP].options
                msg_type = next((v for k, v in opts if k == 'message-type'), None)
                if msg_type == 2:
                    src_ip = packet[IP].src if packet.haslayer(IP) else '0.0.0.0'
                    if src_ip != self.gateway_ip_v4 and src_ip not in self.trusted_ips:
                        self.log_alert(
                            "DHCP_SPOOFING",
                            "Servidor DHCP no autorizado detectado",
                            f"IP servidor sospechoso: {src_ip}, MAC: {packet[Ether].src}",
                            packet=packet,
                        )
        except Exception:
            pass
        
    def get_os_from_ttl(self, ttl: int) -> str:
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco/Solaris"
        else:
            return "Desconocido"
        
    def check_for_credentials(self, packet):
        try:
            if not (packet.haslayer(HTTPRequest) and packet.haslayer(Raw)):
                return
            
            http_layer = packet[HTTPRequest]
            
            if http_layer.Method.decode('utf-8').lower() == 'post':
                raw_payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                keywords = ["password", "user", "login", "pwd", "uname"]
                
                if any(keyword in raw_payload.lower() for keyword in keywords):
                    self.log_alert(
                        "PLAINTEXT_CREDENTIALS",
                        "Credenciales de texto plano detectadas",
                        f"URL: {http_layer.Host.decode('utf-8')}{http_layer.Path.decode('utf-8')}",
                        packet=packet,
                        packet_info=self._extract_malicious_packet_info(packet, "PLAINTEXT_CREDENTIALS")
                    )
        except Exception:
            pass
    
    def handle_tcp_traffic(self, packet, src_ip, dst_ip):
        try:
            if packet.haslayer(TCP):
                tcp_packet = packet[TCP]
                flags_str = ""
                flags = tcp_packet.flags
                
                if flags & 0x02: flags_str += "[bold green]S[/bold green]"
                if flags & 0x10: flags_str += "[bold yellow]A[/bold yellow]"
                if flags & 0x01: flags_str += "[bold red]F[/bold red]"
                if flags & 0x04: flags_str += "[bold red]R[/bold red]"
                if flags & 0x08: flags_str += "[bold cyan]P[/bold cyan]"
                
                protocol = COMMON_PORTS.get(tcp_packet.dport, "Desconocido")
                
                request_info = {
                    'time': time.strftime("%H:%M:%S"),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': tcp_packet.sport,
                    'dst_port': tcp_packet.dport,
                    'flags': flags_str,
                    'protocol': protocol
                }
                
                with self.ui_lock:
                    self.tcp_requests.insert(0, request_info)
                    if len(self.tcp_requests) > self.max_tcp_requests:
                        self.tcp_requests.pop()
        except Exception as e:
            logging.debug(f"Error procesando paquete TCP: {e}")
    
    def check_for_payload_keywords(self, packet):
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
            keywords = ['password', 'login', 'user', 'ftp', 'telnet', 'smtp']
            
            if any(kw in payload for kw in keywords):
                self.log_alert(
                    "PAYLOAD_SENSITIVE_DATA",
                    "Datos sensibles detectados en el paquete",
                    f"Posible protocolo en texto plano",
                    packet=packet
                )

    def _load_local_oui_database(self):
        """Carga una base de datos OUI simple en caso de fallo."""
        self.oui_database = {
            'c8:00:84': 'Dell',
            'f4:30:b9': 'Apple',
            '3c:91:5b': 'Google',
            '2c:0b:4b': 'Samsung',
            'd0:27:01': 'Cisco',
            '00:0c:29': 'VMware',
            '00:1a:11': 'Netgear',
            'ac:3f:a4': 'TP-Link',
            '00:1b:44': 'TP-Link',
            '84:ba:3f': 'Xiaomi',
            '64:9f:8f': 'Huawei',
            '00:00:00': 'XEROX',
            '00:00:0a': 'OMRON Corporation',
            '00:00:0f': 'FUJITSU LIMITED',
            '00:00:1b': 'NEC Corporation',
            '00:00:2a': 'NCR Corporation',
            '00:00:3b': 'SANYO Electric Co., Ltd.',
            '00:00:4e': 'SONY',
            '00:00:5c': '3Com Corporation',
            '00:00:6a': 'IBM',
            '00:00:7e': 'Texas Instruments',
            '00:00:8a': 'Canon Inc.',
            '00:00:9a': 'Nortel Networks',
            '00:00:a7': 'ALCATEL',
            '00:00:b4': 'EPSON',
            '00:00:c8': 'MITSUBISHI ELECTRIC CORPORATION',
            '00:00:d8': 'SAMSUNG ELECTRONICS CO., LTD.',
            '00:00:f0': 'Intel Corporation',
            '00:01:4f': 'Intel Corporation',
            '00:01:8a': 'Motorola Inc.',
            '00:01:e3': 'Hewlett Packard',
        }
        logging.info("Usando base de datos OUI local.")
    
    def get_manufacturer_by_mac(self, mac_address: str):
        """Busca el fabricante de un dispositivo usando los 6 primeros caracteres (OUI) de su MAC."""
        try:

            oui_key = mac_address[:8].upper()

            return self.oui_database.get(oui_key, "Desconocido")
        except Exception:
            return "Desconocido"
    
    def handle_packet(self, packet):
        with self.ui_lock:
            self.packet_count += 1
        
        try:
            src_ip, dst_ip = None, None
            try:
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                elif packet.haslayer(IPv6):
                    src_ip = packet[IPv6].src
                    dst_ip = packet[IPv6].dst
            except Exception:
                pass
            
            if src_ip:
                self._update_fingerprint(src_ip, packet)
                
            self.handle_tcp_traffic(packet, src_ip, dst_ip)
        
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
                    self.check_for_credentials(packet)
                    self.check_for_payload_keywords(packet)
                if packet.haslayer(DHCP):
                    self.handle_dhcp_packet(packet)
            except Exception as e:
                logging.debug(f"Error procesando paquete: {e}")
        except Exception as e:
            logging.debug(f"Error procesando paquete: {e}")

    # -------------------- UI --------------------
    def _init_pagination(self):
        """Inicializa el índice de página y listeners de teclado."""
        self._page_index = 0
        self._devices_per_page = 10

        # Escuchar teclas
        keyboard.add_hotkey("up", self._prev_page)
        keyboard.add_hotkey("down", self._next_page)
        keyboard.add_hotkey("page up", self._prev_page)
        keyboard.add_hotkey("page down", self._next_page)

    def _prev_page(self):
        if not hasattr(self, "_page_index"):
            self._page_index = 0
        self._page_index = max(0, self._page_index - 1)

    def _next_page(self):
        devices = list(self.network_map.items())
        total_pages = max(1, (len(devices) + self._devices_per_page - 1) // self._devices_per_page)
        if not hasattr(self, "_page_index"):
            self._page_index = 0
        self._page_index = min(total_pages - 1, self._page_index + 1)
    
    def generate_network_diagram(self):
        if not DIAGRAM_LIBS_INSTALLED:
            logging.warning("Saltando la generación del diagrama de red. No se encontró `networkx` o `matplotlib`.")
            return

        G = nx.Graph()

        router_ip = self.gateway_ip_v4
        if router_ip and router_ip in self.network_map:
            G.add_node(router_ip, type='router')
        
        for ip, info in self.network_map.items():
            if ip != router_ip:
                G.add_node(ip, type='device')
                G.add_edge(router_ip, ip)

        plt.style.use('mpl20')
        fig, ax = plt.subplots(figsize=(14, 10))
        
        router_pos = {router_ip: (0, 0)} if router_ip in G else {}
        device_nodes = [n for n in G.nodes if n != router_ip]
        if device_nodes:
            device_pos = nx.circular_layout(G.subgraph(device_nodes))
            pos = {**router_pos, **device_pos}
        else:
            pos = router_pos

        node_colors = ['#FF4500' if G.nodes[n]['type'] == 'router' else '#1E90FF' for n in G.nodes()]
        node_sizes = [4500 if G.nodes[n]['type'] == 'router' else 3000 for n in G.nodes()]

        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, ax=ax)

        nx.draw_networkx_edges(G, pos, edge_color='#000', width=2.0, alpha=0.7, ax=ax)

        labels = {
            node: f"Router\n{node}" if G.nodes[node]['type'] == 'router' else f"{self.network_map[node]['mac']}\n{node}"
            for node in G.nodes()
        }
        nx.draw_networkx_labels(G, pos, labels=labels, font_size=10, font_color="#000000", font_weight='bold', ax=ax)

        ax.set_title("Network Map", fontsize=24, color='#FFFFFF', fontname='Arial', fontweight='bold')
        ax.axis('off')
        plt.tight_layout()
        
        # Save the diagram
        self.image_path = "network_diagram.png"
        plt.savefig(self.image_path, format="png", dpi=200)
        plt.close()
    
    def generate_layout(self):
        with self.ui_lock:
            # Paneles de la columna izquierda
            left_panels = [
                Panel(
                    f"[bold white]Estado:[/] {'[bold green]Activo[/]' if self.active else '[bold red]Detenido[/]'}\n"
                    f"[bold white]Interfaz:[/] {self.interface}\n"
                    f"[bold white]Gateway IPv4:[/] {self.gateway_ip_v4} ({self.gateway_mac_v4})\n"
                    f"[bold white]Paquetes procesados:[/] {self.packet_count}",
                    title="Estado de Detección",
                    border_style="green",
                    width=100,
                ),
                self.generate_network_map_panel(width=100),
                self.generate_tcp_panel(width=100),
                self.generate_protocols_panel(width=100),
                self.generate_unusual_dns_panel(width=100)
            ]

            # Paneles de la columna derecha
            right_panels = [
                self.generate_alerts_panel(width=120),
                self.generate_packet_panel(width=120)
            ]

            return Columns(
                [
                    Group(*left_panels),
                    Group(*right_panels)
                ],
                expand=True
            )

    def generate_network_map_panel(self, width):
        devices = list(self.network_map.items())
        total_pages = max(1, (len(devices) + self._devices_per_page - 1) // self._devices_per_page)
        start = self._page_index * self._devices_per_page
        end = start + self._devices_per_page
        current_devices = devices[start:end]

        network_map_table = Table(
            title=f"[b]Dispositivos de la Red (página {self._page_index+1}/{total_pages})[/b]",
            style="dim",
            padding=(0,0),
            show_header=True,
            width=95
        )
        network_map_table.add_column("[b]IP[/b]", justify="left", no_wrap=True)
        network_map_table.add_column("[b]MAC[/b]", justify="left", no_wrap=True)
        network_map_table.add_column("[b]Fabricante[/b]", justify="left", no_wrap=True)
        network_map_table.add_column("[b]OS[/b]", justify="left", no_wrap=True)
        network_map_table.add_column("[b]Estado[/b]", justify="left", no_wrap=True)
        network_map_table.add_column("[b]Puertos[/b]", justify="left", no_wrap=True)

        for ip, info in current_devices:
            status = "Router" if info.get('is_router') else "Dispositivo"
            ports = ','.join(map(str, sorted(list(self.open_ports.get(ip, set()))))) or "Escaneando..."
            os_info = info.get('os_type', 'N/A')
            manufacturer = info.get('manufacturer', 'N/A')
            network_map_table.add_row(ip, info['mac'], manufacturer, os_info, status, ports)

        return Panel(
            network_map_table,
            title="[b]Mapa de la Red[/b]",
            border_style="blue",
            width=width
        )

    def generate_tcp_panel(self, width):
        tcp_table = Table(title="[b]Últimas Peticiones TCP[/b]", style="dim", padding=(0,0), width=95)
        tcp_table.add_column("[b]Hora[/b]", justify="left", no_wrap=True)
        tcp_table.add_column("[b]IP Origen[/b]", justify="left", no_wrap=True)
        tcp_table.add_column("[b]Pto. Origen[/b]", justify="left", no_wrap=True)
        tcp_table.add_column("[b]IP Destino[/b]", justify="left", no_wrap=True)
        tcp_table.add_column("[b]Pto. Destino[/b]", justify="left", no_wrap=True)
        tcp_table.add_column("[b]Flags[/b]", justify="left", no_wrap=True)

        for req in self.tcp_requests:
            tcp_table.add_row(
                req['time'],
                req['src_ip'],
                str(req['src_port']),
                req['dst_ip'],
                str(req['dst_port']),
                req['flags']
            )
        return Panel(tcp_table, title="[b]Trafico TCP[/b]", border_style="magenta", width=width)

    def generate_protocols_panel(self, width):
        protocols_table = Table(
            title="[b]Protocolos Detectados[/b]",
            style="dim",
            padding=(0,0),
            width=95
        )
        protocols_table.add_column("[b]Hora[/b]", justify="left", no_wrap=True)
        protocols_table.add_column("[b]Protocolo[/b]", justify="left", no_wrap=True)
        protocols_table.add_column("[b]IP Origen[/b]", justify="left", no_wrap=True)
        protocols_table.add_column("[b]Pto. Destino[/b]", justify="left", no_wrap=True)
        
        for req in self.tcp_requests:
            protocols_table.add_row(
                req['time'],
                req['protocol'],
                req['src_ip'],
                str(req['dst_port'])
            )
        return Panel(protocols_table, title="[b]Protocolos Detectados[/b]", border_style="cyan", width=width)

    def generate_alerts_panel(self, width):
        alerts_panel_content = ""
        recent_alerts = self.alerts[-3:] 
        for timestamp, alert in recent_alerts:
            alerts_panel_content += f"[bold red]{timestamp}[/] - [bold yellow]{alert}[/]\n"
        return Panel(
            alerts_panel_content,
            title="Alertas de Seguridad",
            border_style="red",
            width=width
        )
    
    def generate_unusual_dns_panel(self, width):
        """Genera un panel que muestra búsquedas de DNS inusuales."""
        table = Table(title="[b]Búsquedas DNS Inusuales[/b]", style="dim", padding=(0,0), width=95)
        table.add_column("[b]Hora[/b]", justify="left", no_wrap=True)
        table.add_column("[b]Origen[/b]", justify="left", no_wrap=True)
        table.add_column("[b]Dominio[/b]", justify="left", no_wrap=True)

        unusual_queries_copy = self.unusual_dns_queries.copy()

        for time_str, src_ip, domain in unusual_queries_copy:
            table.add_row(time_str, src_ip, domain)
        
        return Panel(
            table,
            title="[b]Búsquedas DNS Inusuales[/b]",
            border_style="purple",
            width=width
        )

    def generate_packet_panel(self, width):
        if self.recent_malicious_packet:
            packet_dump = self.recent_malicious_packet.show2(dump=True)
            syntax = Syntax(packet_dump, "go", theme="monokai", line_numbers=True)
            return Panel(syntax, title="Detalles del Paquete Malicioso", width=width, height=65)
        else:
            return Panel("[bold dim]Esperando paquetes...[/]", title="Detalles del Paquete Malicioso", border_style="dim", width=width, height=65)

    def start_ui(self):
        if self.log_only:
            while self.active and not self.stop_event.is_set():
                if self.stop_event.wait(0.5):
                    break
            return
        with Live(self.generate_layout(), screen=True, auto_refresh=True, vertical_overflow="visible") as live:
            while self.active and not self.stop_event.is_set():
                live.update(self.generate_layout())
                if self.stop_event.wait(0.5):
                    break

    # -------------------- runtime --------------------
    def start_passive_detection(self):
        try:
            sniff(prn=self.handle_packet, iface=self.interface, store=0, stop_filter=lambda p: self.stop_event.is_set())
        except Exception as e:
            logging.error(f"Error iniciando sniffer: {e}")
            self.stop()

    def run(self):
        self.discover_network_devices()
        if self.test_mode:
            self.test_dns_spoofing()
            return
        threads: List[threading.Thread] = []
        sniffer_thread = threading.Thread(target=self.start_passive_detection, daemon=True)
        sniffer_thread.start()
        threads.append(sniffer_thread)
        arp_monitor_thread = threading.Thread(target=self.monitor_arp_cache, daemon=True)
        arp_monitor_thread.start()
        threads.append(arp_monitor_thread)
        port_scan_thread = threading.Thread(target=self._port_scan_worker, daemon=True)
        port_scan_thread.start()
        threads.append(port_scan_thread)
        if self.active_scan:
            scan_thread = threading.Thread(target=self.run_periodic_scans, daemon=True)
            scan_thread.start()
            threads.append(scan_thread)
        if self.countermeasures and not self.passive_mode:
            countermeasure_thread = threading.Thread(target=self.run_active_countermeasures, daemon=True)
            countermeasure_thread.start()
            threads.append(countermeasure_thread)
        try:
            self.start_ui()
        except KeyboardInterrupt:
            self.stop()
        finally:
            for t in threads:
                t.join(timeout=2)

    def stop(self):
        self.generate_network_diagram()
        self.active = False
        self.stop_event.set()


# -------------------- CLI --------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detector/Mitigador MitM optimizado (español).")
    parser.add_argument('-i', '--interface', required=True, help="Interfaz a monitorear (ej. eth0, wlan0).")
    parser.add_argument('-c', '--countermeasures', action='store_true', help="Activa contramedidas (ARP/ND).")
    parser.add_argument('-p', '--passive', action='store_true', help="Modo pasivo (solo detección).")
    parser.add_argument('--trusted-ips', type=str, help="IPs confiables separadas por comas.")
    parser.add_argument('-t', '--test', action='store_true', help="Modo prueba: simula DNS spoofing.")
    parser.add_argument('--json-out', type=str, help="Archivo JSONL para exportar alertas.")
    parser.add_argument('--no-active-scan', action='store_true', help="Desactiva escaneo activo periódico.")
    parser.add_argument('--log-only', action='store_true', help="No iniciar UI Rich; solo logs.")
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'], help="Nivel de logging.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None):
    args = parse_args(argv)
    trusted_ips_list = [ip.strip() for ip in (args.trusted_ips.split(',') if args.trusted_ips else []) if ip.strip()]
    detector = MitMDetection(
        interface=args.interface,
        countermeasures=args.countermeasures,
        passive_mode=args.passive,
        trusted_ips=trusted_ips_list,
        test_mode=args.test,
        json_out=args.json_out,
        active_scan=not args.no_active_scan,
        log_only=args.log_only,
        log_level=args.log_level,
    )
    detector.run()

if __name__ == '__main__':
    main()
