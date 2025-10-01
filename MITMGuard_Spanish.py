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
import ssl
import dns.resolver
import subprocess
import re
import math
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
from typing import Dict, List, Optional, Set, Tuple, Union, Any

from datetime import datetime
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
    Raw,
    rdpcap
)
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import getmacbyip
from scapy.layers.http import HTTPRequest
from scapy.layers.dhcp import DHCP
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6ND_NS


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

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

log_path = os.path.join(BASE_DIR, "mitm_debug.log")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path),
    ]
)

gui_logger = logging.getLogger(__name__)
gui_logger.setLevel(logging.INFO) # DEBUG, INFO, WARNING, ERROR

COLORS = {
    'bg_primary': '#ECEFF1',      # Gris muy claro, casi blanco
    'bg_secondary': '#CFD8DC',    # Gris claro para paneles
    'text_color': '#263238',      # Gris oscuro, casi negro
    'highlight_color': '#64B5F6', # Azul claro vibrante para selecciones
    'border_color': '#90A4AE',    # Gris azulado para bordes
    'button_bg': '#B0BEC5',       # Gris medio para botones
    'accent_color': '#00B0FF',    # Azul brillante para acentos
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

class DeviceInventory:
    def __init__(self, base_dir: str):
        self.inventory_file = os.path.join(base_dir, "device_inventory.json")
        # Estructura: { 'ip_o_mac': {'name': 'Router', 'trusted': True, 'risk_score': 0, 'last_seen': 1678886400} }
        self.inventory: Dict[str, Dict[str, Any]] = {}
        self._load_inventory()

    def _load_inventory(self):
        if os.path.exists(self.inventory_file):
            try:
                with open(self.inventory_file, 'r', encoding='utf-8') as f:
                    self.inventory = json.load(f)
            except Exception:
                self.inventory = {}
        
    def save_inventory(self):
        try:
            os.makedirs(os.path.dirname(self.inventory_file), exist_ok=True)
            with open(self.inventory_file, 'w', encoding='utf-8') as f:
                json.dump(self.inventory, f, indent=4)
        except Exception:
            pass
            
    def get_device_info(self, key: str) -> Dict[str, Any]:
        now = time.time()
        info = self.inventory.setdefault(key, {
            'name': key, 
            'trusted': False, 
            'risk_score': 0, 
            'last_seen': now
        })
        info['last_seen'] = now
        return info

    def set_device_name(self, key: str, name: str):
        self.get_device_info(key)['name'] = name
        self.save_inventory()
        
    def update_risk_score(self, key: str, score_change: int):
        info = self.get_device_info(key)
        info['risk_score'] = max(0, info.get('risk_score', 0) + score_change)
        self.save_inventory()
        return info['risk_score']

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
        self.graph_packet_count = 0
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
        self.dhcp_requests = {}
        self.dhcp_request_threshold = 20
        self.dhcp_check_interval = 1
        self.packet_history = []
        self.history_size = 5
        self.last_packet_check = time.time()
        self.ip_to_domain_map: Dict[str, str] = {}
        self.tracker_domains: List[str] = self._load_tracker_domains()
        self.tracking_attempts: List[Dict[str, Any]] = []
        self.json_out_file = json_out
        self.jsonl_lock = threading.Lock()
        self.dns_verify_cert = False
        self.dns_verify_timeout = 2.0
        self.dns_verify_maxips = 5
        self._dns_verif_cache = {}
        self.inventory_manager = DeviceInventory(BASE_DIR)
        self.tcp_flow_tracking: Dict[Tuple, int] = {}
        self.MAX_RISK_SCORE = 15
        
        if self.json_out:
            json_path = self.json_out
            if not os.path.isabs(json_path):
                json_path = os.path.join(BASE_DIR, os.path.basename(self.json_out))
                
            try:
                with open(json_path, 'w', encoding="utf-8") as f:
                    f.truncate(0)
                logging.debug(f"Archivo JSONL {json_path} vaciado al inicio")
            except Exception as e:
                logging.error(f"Error al vaciar el archivo JSONL {json_path}: {e}")

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
        logging_path = os.path.join(BASE_DIR, "mitm_detector.log")
        logging.basicConfig(
            level=lvl,
            format='%(message)s',
            datefmt='[%X]',
            handlers=[
                logging.FileHandler(logging_path, mode='a'),
            ],
        )
        
    def _load_tracker_domains(self) -> List[str]:
        """Carga una lista de dominios de rastreadores desde un archivo."""
        tracker_file = os.path.join(BASE_DIR, "tracker_domains.txt")
        if os.path.exists(tracker_file):
            with open(tracker_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.console.print(f"[bold blue]Cargados {len(domains)} dominios de rastreo conocidos.[/bold blue]")
            return domains
        else:
            self.console.print(f"[bold yellow]Advertencia: No se encontró el archivo '{tracker_file}'. La detección de rastreadores no estará activa.[/bold yellow]")
            return []

    # -------------------- logging & alerts --------------------
    def _write_json_event(self, payload: dict):
        if not self.json_out:
            return
        try:
            out_path = self.json_out
            if not os.path.isabs(out_path):
                out_path = os.path.join(BASE_DIR, os.path.basename(self.json_out))
                
            with open(out_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as e:
            logging.error(f"Error escribiendo evento JSON: {e}")

    def log_malicious_packet(self, packet, alert_type: str):
        try:
            filename = os.path.join(BASE_DIR, f"{alert_type.lower()}_alerts.pcap")
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
    def _check_for_trackers(self, src_ip: str, dst_domain: str):
        for tracker_domain in self.tracker_domains:
            if tracker_domain in dst_domain: 
                # Ahora añadimos un nuevo diccionario para cada intento detectado
                # Podemos añadir un timestamp si queremos
                attempt_info = {
                    "src_ip": src_ip,
                    "tracker_domain": tracker_domain,
                    "full_dst_domain": dst_domain, # El dominio exacto al que se conectó
                    "timestamp": time.time()
                }
                self.tracking_attempts.append(attempt_info)
                
                self.log_alert( # Esto genera el log y debería actualizar la UI
                    "TRACKING_ATTEMPT", 
                    f"Intento de Rastreo Detectado desde {src_ip}",
                    f"Dispositivo {src_ip} conectado a dominio de rastreo: {dst_domain}"
                )
                self.console.print(f"[bold magenta]ALERTA TRACKER:[/bold magenta] {dst_domain} desde {src_ip}") 
                return # Detener al encontrar el primer match para este paquete
    
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
                ips_to_scan = list(self.network_map.keys())
                for ip in ips_to_scan:
                    if ip not in self.open_ports:
                        with self.ui_lock:
                            self.open_ports[ip] = set()
                        self._scan_ports(ip)
            if self.stop_event.wait(30):
                break

    def _scan_ports(self, ip: str):
        ports_to_scan = [22, 25, 80, 139, 443, 445, 3389, 8080]
        if ":" in ip:
            socket_family = socket.AF_INET6
            connect_tuple = (ip, 0, 0, 0)
        else:
            socket_family = socket.AF_INET
            connect_tuple = (ip, 0)

        for port in ports_to_scan:
            with socket.socket(socket_family, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                try:
                    if socket_family == socket.AF_INET6:
                        connect_tuple_ipv6 = (ip, port, 0, 0)
                        if sock.connect_ex(connect_tuple_ipv6) == 0:
                            with self.ui_lock:
                                self.open_ports[ip].add(port)
                    else:
                        if sock.connect_ex((ip, port)) == 0:
                            with self.ui_lock:
                                self.open_ports[ip].add(port)
                except Exception as e:
                    logging.debug(f"Error en escaneo de puerto {ip}:{port}: {e}")

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

                src_ip = "N/A"
                if packet.haslayer(IP):
                    src_ip = packet.getlayer(IP).src
                else:
                    logging.debug("DEBUG: Paquete DNS de consulta sin capa IP. src_ip será N/A.")

                dns_query = ""
                if packet.haslayer(DNS) and packet.getlayer(DNS).qd:
                    try:
                        dns_query = packet.getlayer(DNS).qd.qname.decode('utf-8').strip('.')
                    except Exception as e:
                        logging.warning(f"Error decodificando qname en DNS query: {e}")
                        return
                else:
                    logging.debug("DEBUG: Paquete DNS de consulta sin qd o sin DNS layer esperado.")
                    return

                logging.debug(f"DEBUG: En check_dns_query - src_ip: {src_ip}, dns_query: {dns_query}, longitud: {len(dns_query)}")

                is_unusual = False
                unusual_reason = ""

                # Check 1: Longitud del subdominio (parte principal)
                parts = dns_query.split('.')
                if parts and len(parts[0]) > 30:
                    is_unusual = True
                    unusual_reason = f"Subdominio inusualmente largo ({len(parts[0])} caracteres)"
                    logging.debug(f"DEBUG: DNS Inusual - Longitud detectada: {dns_query}")
                    
                parts = dns_query.split('.')
                if parts:
                    subdomain_data = parts[0].encode('utf-8')
                    entropy_score = self.calculate_shannon_entropy(subdomain_data)
                    
                    if entropy_score > 4.5:
                        is_unusual = True
                        unusual_reason = f"Alta Entropia ({entropy_score:.2f} en el subdominio. Posible Tunel DNS)"
                        logging.debug(f"DEBUG: DNS Inusual - Alta Entropía detectada: {dns_query}")
            

                # Check 2: TLD sospechoso (si no es inusual por longitud)
                if not is_unusual:
                    tld = parts[-1] if len(parts) > 0 else ""
                    if tld == "":
                        tld = parts[-2] if len(parts) > 1 else ""
                    
                    if tld in ["ru", "bit", "cc", "ga", "ml", "tk"]:
                        is_unusual = True
                        unusual_reason = f"TLD sospechoso: .{tld}"
                        logging.debug(f"DEBUG: DNS Inusual - TLD sospechoso detectado: {dns_query}")

                if is_unusual:
                    with self.ui_lock:
                        alert_tuple = (time.strftime("%H:%M:%S"), src_ip, dns_query)
                        self.unusual_dns_queries.append(alert_tuple)
                        logging.debug(f"DEBUG: DNS Inusual Añadido a la lista: {alert_tuple}")

                        if len(self.unusual_dns_queries) > 20:
                            self.unusual_dns_queries.pop(0)
                        
                        self.log_alert("DNS_EXFILTRATION", f"Consulta DNS inusual ({unusual_reason} desde {src_ip})", f"Consulta: {dns_query}", log_level=logging.WARNING)

        except Exception as e:
            logging.error(f"Error CRÍTICO en check_dns_query: {e}", exc_info=True)
    
    def _match_hostname(self, hostname: str, pattern: str) -> bool:
        hostname = hostname.lower().rstrip('.')
        pattern = pattern.lower().rstrip('.')
        
        if pattern == hostname:
            return True
        if pattern.startswith('*.'):
            suffix = pattern[2:]
            return hostname.endswith('.' + suffix)
        return False
    
    def _is_ip_in_resolvers(self, domain: str, ip_list:List[str]) -> bool:
        try:
            valid_ips = self.dns_cache.resolve_a(domain)
        except Exception:
            valid_ips = set()
        
        if not valid_ips:
            return False
        
        for ip in ip_list:
            if ip in valid_ips:
                return True
        return False
    
    def _verify_cert_for_ip(self, ip: str, domain: str) -> bool:
        key = (domain.lower(), ip)
        if key in self.dns_verif_cache:
            return bool(self._dns_verif_cache[key])
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((ip, 443), timeout=self.dns_verify_timeout) as sock:
                with ctx.warp_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    san = cert.get("subjectAltName", ())
                    for typ, val in san:
                        if typ.lower() in ('dns',) and self._match_hostname(domain, val):
                            self._dns_verif_cache[key] = True
                            return True
                        
                    subject = cert.get('subject', ())
                    for part in subject:
                        for k, v in part:
                            if k.lower() == 'commonname' and self._match_hostname(domain, v):
                                self._dns_verif_cache[key] = True
                                return True
        except Exception:
            pass
        
        self._dns_verif_cache[key] = False
        return False
    
    def calculate_shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        data_len = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def check_icmp_tunneling(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer("ICMP")):
            return
            
        ip_layer = packet[IP]

        if packet["ICMP"].type not in [8, 0]:
            return

        raw_payload = bytes(packet[Raw].load) if packet.haslayer(Raw) else b''
        payload_len = len(raw_payload)

        if payload_len > 100:
            entropy_score = self.calculate_shannon_entropy(raw_payload) 
            
            self.log_alert(
                "ICMP_TUNNELING", 
                "Payload de ICMP inusualmente grande",
                f"Payload de {payload_len} bytes. Entropía: {entropy_score:.2f}. Posible túnel ICMP C2 entre {ip_layer.src} y {ip_layer.dst}.",
                packet=packet,
                log_level=logging.CRITICAL
            )
            self.inventory_manager.update_risk_score(ip_layer.src, 5)

        flow_key = tuple(sorted((ip_layer.src, ip_layer.dst)))
        now = time.time()
        
        self.icmp_traffic.setdefault(flow_key, []).append(now)
        self.icmp_traffic[flow_key] = [t for t in self.icmp_traffic[flow_key] if now - t < 5] 

        if len(self.icmp_traffic[flow_key]) > 20:
            self.log_alert(
                "ICMP_FLOOD_ANOMALY",
                "Tráfico ICMP de alta frecuencia",
                f"Se detectaron {len(self.icmp_traffic[flow_key])} pings en 5 segundos entre {ip_layer.src} y {ip_layer.dst}.",
                packet=packet,
                log_level=logging.WARNING
            )

    def check_ttl_hop_anomaly(self, packet):
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ttl = ip_layer.ttl

        if src_ip not in self.trusted_ips and src_ip != self.my_ip_v4:
            return
            
        ttl_base = 0
        if ttl <= 64: ttl_base = 64
        elif ttl <= 128: ttl_base = 128
        elif ttl <= 255: ttl_base = 255
        
        if ttl_base == 0:
            return

        hop_count = ttl_base - ttl + 1
        
        if dst_ip not in self.hop_baseline:
            self.hop_baseline[dst_ip] = hop_count
            return
            
        baseline = self.hop_baseline[dst_ip]

        if hop_count >= baseline + 1:
            self.log_alert(
                "HOP_COUNT_INCREASE",
                f"Aumento de saltos inesperado a {dst_ip}",
                f"Saltos: {baseline} -> {hop_count}. Un atacante podría haberse inyectado en la ruta (Man-in-the-Middle L3).",
                packet=packet,
                log_level=logging.CRITICAL
            )
            self.inventory_manager.update_risk_score(src_ip, 5)
        elif hop_count < baseline:
            self.hop_baseline[dst_ip] = hop_count
    
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
            low_ttl_detected = False
            ancount = int(getattr(packet[DNS], 'ancount', 0) or 0)
            if ancount > 0 and getattr(packet[DNS], 'an', None):
                ans = packet[DNS].an
                for _ in range(ancount):
                    if getattr(ans, 'type', None) == 1 and hasattr(ans, 'rdata'):
                        packet_resolved_ips.append(str(ans.rdata))
                        if hasattr(ans, 'ttl') and ans.ttl < 60:
                            low_ttl_detected = True
                    ans = getattr(ans, 'payload', None)
                    if ans is None:
                        break

            if not packet_resolved_ips:
                self.log_alert("DNS_RESPUESTA_VACIA", f"Respuesta DNS vacía para '{query_name}'", "Posible error de captura; no es un ataque")
                return

            if self._is_ip_in_resolvers(query_name, packet_resolved_ips):
                self.dns_responses[query_name] = set(packet_resolved_ips)
                return

            valid_ips = self.dns_cache.resolve_a(query_name)

            if not valid_ips:
                self.log_alert("DNS_UNVERIFIED", f"No se pudieron validar IPs para '{query_name}'", f"Recibido: {packet_resolved_ips}", packet=packet)
                self.dns_responses[query_name] = set(packet_resolved_ips)
                return

            if self.dns_verify_cert and len(packet_resolved_ips) <= self.dns_verify_maxips:
                verified_any = False
                for ip in packet_resolved_ips:
                    try:
                        if self._verify_cert_for_ip(ip, query_name):
                            verified_any = True
                            break
                    except Exception:
                        continue
                if verified_any:
                    self.dns_responses[query_name] = set(packet_resolved_ips)
                    return
                else:
                    self.log_alert(
                        "DNS_SPOOFING",
                        f"Respuesta DNS inválida para '{query_name}' (no coincide con resolvers y cert no valida)",
                        f"Se esperaba: {sorted(valid_ips)}; Recibido: {packet_resolved_ips}",
                        packet=packet,
                    )
                    self.dns_responses[query_name] = set(packet_resolved_ips)
                    return
                
            if low_ttl_detected:
                self.log_alert(
                    "DNS_LOW_TTL", 
                    f"TTL Inusualmente Bajo en Respuesta DNS para '{query_name}'", 
                    f"Se recibió un TTL < 60s. Indicador común de Spoofing DNS activo. IPs: {packet_resolved_ips}", 
                    packet=packet,
                    log_level=logging.WARNING
                )

            self.log_alert(
                "DNS_UNVERIFIED",
                f"Respuesta DNS inusual para '{query_name}'",
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
    
    def check_anomalous_packets(self, packet):
        """Verifica el paquete en busca de anomalías que puedan indicar una inyección."""
        try:
            if packet.haslayer(Ether) and packet[Ether].src == packet[Ether].dst:
                self.log_alert(
                    "PACKET_INJECTION",
                    "Paquete con MAC de origen y destino idénticas",
                    f"MAC: {packet[Ether].src}",
                    packet=packet,
                    log_level=logging.CRITICAL
                )
            if packet.haslayer(Ether):
                packet_len = len(packet)
                if packet_len > 1518 or packet_len < 64:
                    self.log_alert(
                        "PACKET_INJECTION",
                        "Paquete con tamaño inusual",
                        f"Tamaño de paquete: {packet_len} bytes",
                        packet=packet,
                        log_level=logging.WARNING
                    )

        except Exception as e:
            self.logger.error(f"Error en check_anomalous_packets: {e}")
    
    def handle_dhcp_packet(self, packet):
        """Maneja paquetes DHCP y busca ataques de spoofing y starvation."""
        try:
            if packet.haslayer(DHCP):
                opts = dict(packet[DHCP].options)
                msg_type = opts.get('message-type')

                if msg_type == 1:
                    mac_src = packet[Ether].src
                    now = time.time()

                    self.dhcp_requests[mac_src] = [
                        t for t in self.dhcp_requests.get(mac_src, [])
                        if now - t < self.dhcp_check_interval
                    ]
                    self.dhcp_requests.setdefault(mac_src, []).append(now)

                    if len(self.dhcp_requests[mac_src]) > self.dhcp_request_threshold:
                        self.log_alert(
                            "DHCP_STARVATION",
                            "Posible ataque de agotamiento de direcciones IP",
                            f"La MAC {mac_src} está enviando demasiadas peticiones DHCP. Total: {len(self.dhcp_requests[mac_src])}",
                            packet=packet,
                            log_level=logging.WARNING
                        )

                elif msg_type == 2:
                    src_ip = packet[IP].src if packet.haslayer(IP) else '0.0.0.0'
                    src_mac = packet[Ether].src
                    if src_ip != self.gateway_ip_v4 and src_ip not in self.trusted_ips:
                        self.log_alert(
                            "DHCP_SPOOFING",
                            "Servidor DHCP no autorizado detectado",
                            f"IP sospechosa: {src_ip}, MAC: {src_mac}",
                            packet=packet,
                            log_level=logging.CRITICAL
                        )
                    else:
                        rogue_params = []
                    
                    options = dict(packet[DHCP].options)
                    router_ip = options.get('router', [None])[0]
                    dns_servers = options.get('name_server', [])

                    if router_ip and router_ip != self.gateway_ip_v4:
                        rogue_params.append(f"Router ({router_ip}) no coincide con el gateway conocido ({self.gateway_ip_v4})")

                    for dns_ip in dns_servers:
                        if dns_ip not in self.trusted_ips:
                            rogue_params.append(f"Servidor DNS ({dns_ip}) no está en la lista de confianza")
                            
                    if rogue_params:
                        self.log_alert(
                            "DHCP_PARAM_INJECTION",
                            "Servidor DHCP inyectando parámetros maliciosos",
                            f"MAC: {src_mac}, Problemas: {'; '.join(rogue_params)}",
                            packet=packet,
                            log_level=logging.CRITICAL
                        )
        except Exception as e:
            self.logger.error(f"Error en handle_dhcp_packet: {e}")
        
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
        
    def _check_sensitive_protocol_payload(self, packet):
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return

        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        raw_payload = packet[Raw].load.decode('utf-8', errors='ignore')

        port = src_port if dst_port in [21, 23, 110] else dst_port
        protocol = COMMON_PORTS.get(port)
        
        if protocol in ["FTP", "Telnet", "POP3", "IMAP"]:
            credential_keywords = ["USER", "PASS", "LOGIN", "AUTH"]
            
            for keyword in credential_keywords:
                if keyword in raw_payload.upper():
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    
                    self.log_alert(
                        f"{protocol}_CREDENTIALS",
                        f"Credenciales potenciales sin cifrar {protocol}",
                        f"Fuente: {src_ip}:{src_port} -> {dst_ip}:{dst_port}. La carga útil contiene una palabra clave '{keyword}'.",
                        packet=packet
                    )
                    new_score = self.inventory_manager.update_risk_score(src_ip, 3)
                    if new_score >= self.MAX_RISK_SCORE:
                        self.log_alert("RIESGO CRÍTICO", f"El dispositivo {src_ip} alcanzó la puntuación de riesgo máxima", f"Se detectó transmisión de credenciales y otra actividad sospechosa (Puntuación: {new_score})")
                    return
                
    def _check_tcp_sequence_anomaly(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return
            
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        flow_key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
        current_seq = tcp_layer.seq

        if flow_key in self.tcp_flow_tracking:
            last_seq = self.tcp_flow_tracking[flow_key]

            if current_seq > last_seq:
                diff = current_seq - last_seq

                if diff > 100000 and len(tcp_layer.payload) < 50:
                    self.log_alert(
                        "TCP_SEQ_ANOMALY",
                        f"Salto de secuencia TCP extremo ({diff} bytes))",
                        f"El host {ip_layer.src} envió una secuencia inesperada. Posible intento de secuestro de sesión.",
                        packet=packet
                    )
                    self.inventory_manager.update_risk_score(ip_layer.src, 5)

        self.tcp_flow_tracking[flow_key] = current_seq
    
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
        if not self.active:
            return

        with self.ui_lock:
            self.packet_count += 1
            self.graph_packet_count += 1
            now = time.time()
            
            if now - self.last_packet_check >= 1:
                pps = self.graph_packet_count / (now - self.last_packet_check)
                self.packet_history.append(pps)
                self.packet_history = self.packet_history[-self.history_size:]
                self.graph_packet_count = 0
                self.last_packet_check = now
        
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

            if packet.haslayer(DNS):
                self.check_dns_query(packet)
                if packet.qr == 1: 
                    for i in range(packet[DNS].ancount):
                        try:
                            dnsrr = packet[DNSRR][i]
                            if dnsrr.type == 1:
                                domain = dnsrr.rrname.decode('utf-8', errors='ignore').strip('.')
                                ip_resolved = dnsrr.rdata
                                self.ip_to_domain_map[str(ip_resolved)] = domain
                        except IndexError:
                            continue
                        except Exception as e:
                            logging.warning(f"Error procesando registro DNS en respuestas: {e}")

            if src_ip and dst_ip and TCP in packet and (packet[TCP].dport == 80 or packet[TCP].dport == 443):
                dst_domain = None
                if packet[TCP].dport == 80 and Raw in packet:
                    try:
                        http_payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        host_lines = [line for line in http_payload.split('\n') if "Host:" in line]
                        if host_lines:
                            dst_domain = host_lines[0].split("Host:")[1].strip()
                    except Exception as e:
                        pass
                if not dst_domain and str(dst_ip) in self.ip_to_domain_map:
                    dst_domain = self.ip_to_domain_map[str(dst_ip)]
                if dst_domain:
                    self._check_for_trackers(src_ip, dst_domain)

            if src_ip:
                self._update_fingerprint(src_ip, packet)
            self.handle_tcp_traffic(packet, src_ip, dst_ip)

            try: 
                if packet.haslayer(ARP):
                    self.handle_arp(packet)
                if packet.haslayer(ICMPv6ND_RA) or packet.haslayer(ICMPv6ND_NA) or packet.haslayer(ICMPv6ND_NS):
                    self.handle_ipv6_nd(packet)
                self.check_dns_response(packet)
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    self._update_fingerprint(src_ip, packet)
                    self._check_tcp_sequence_anomaly(packet)
                    self.check_anomalous_packets(packet)
                if packet.haslayer(HTTPRequest):
                    self.check_for_sslstrip(packet)
                    self.check_for_credentials(packet)
                    self.check_for_payload_keywords(packet)
                self._check_sensitive_protocol_payload(packet)
                if packet.haslayer(DHCP):
                    self.handle_dhcp_packet(packet)
                if self.fingerprint_changed(src_ip):
                    self.inventory_manager.update_risk_score(src_ip, 2)
                    
                score = self.inventory_manager.get_device_info(src_ip)['risk_score']
                if score > 0:
                    logging.info(f"[*] Dispositivo {src_ip} Puntuacion de riesgo: {score}")
            except Exception as e:
                logging.debug(f"Error de procesamiento de paquetes: {e}")
        except Exception as e:
            logging.debug(f"Error de procesamiento de paquetes: {e}")

    # -------------------- UI --------------------
    def _init_pagination(self):
        """Inicializa el índice de página y listeners de teclado."""
        self._page_index = 0
        self._devices_per_page = 10

        # Escuchar teclas
        keyboard.add_hotkey("f2", self._prev_page)
        keyboard.add_hotkey("f3", self._next_page)

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
        self.image_path = os.path.join(BASE_DIR,"network_diagram.png")
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
                self.generate_packet_panel(width=120),
                self.generate_traffic_graph_panel(width=120),
                self.generate_tracking_attempts_panel(width=120)
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
    
    def generate_unusual_dns_panel(self, width: int) -> Panel:
        """Genera un panel que muestra búsquedas de DNS inusuales."""

        table_width = width - 4

        table = Table(
            title="[b]Búsquedas DNS Inusuales[/b]", 
            style="dim", 
            padding=(0,1),
            width=table_width,
            show_header=True,
            header_style="bold green" 
        )

        table.add_column("[b]Hora[/b]", justify="left", no_wrap=True, width=10)
        table.add_column("[b]Origen[/b]", justify="left", no_wrap=True, width=15)
        table.add_column("[b]Dominio[/b]", justify="left", no_wrap=False, max_width=table_width - 10 - 15 - 4)

        if not self.unusual_dns_queries:

            table.add_row(
                Text("", style="dim"),
                Text("No se han detectado", style="dim"),
                Text("búsquedas DNS inusuales...", style="dim")
            )
        else:
            for time_str, src_ip, domain in self.unusual_dns_queries[-5:]:
                display_domain = domain
                if len(display_domain) > (table_width - 10 - 15 - 4): 
                    display_domain = display_domain[:(table_width - 10 - 15 - 4 - 3)] + "..."
                
                table.add_row(time_str, src_ip, display_domain, style="yellow")

        return Panel(
            table,
            title="[b]Búsquedas DNS Inusuales[/b]",
            border_style="yellow",
            width=width
        )

    def generate_packet_panel(self, width):
        if self.recent_malicious_packet:
            packet_dump = self.recent_malicious_packet.show2(dump=True)
            syntax = Syntax(packet_dump, "go", theme="monokai", line_numbers=True)
            return Panel(syntax, title="Detalles del Paquete Malicioso", width=width, height=40)
        else:
            return Panel("[bold dim]Esperando paquetes...[/]", title="Detalles del Paquete Malicioso", border_style="dim", width=width, height=40)
        
    def generate_traffic_graph_panel(self, width: int):
        """Genera un panel con un gráfico de tráfico de paquetes por segundo."""
        if not self.packet_history:
            return Panel(
                Text("Esperando datos de tráfico...", justify="center"),
                title="[b]Gráfico de Tráfico[/b]",
                border_style="yellow",
                width=width
            )

        max_pps = max(self.packet_history) if self.packet_history else 1
        graph_data = [int((pps / max_pps) * (width - 10)) for pps in self.packet_history]

        block_chars = " ▏▎▍▌▋▊▉█"

        graph_text = Text()
        for i, pps in enumerate(self.packet_history):
            bar_len = graph_data[i]
            bar_str = block_chars[-1] * bar_len
            if bar_str == "" and pps > 0:
                bar_str = block_chars[1]

            graph_text.append(bar_str, style="blue")
            graph_text.append(f" {pps:.2f} pps\n", style="dim")

        return Panel(
            graph_text,
            title=f"[b]Tráfico de la Red (pps)[/b] - Max: {max_pps:.2f}",
            border_style="yellow",
            width=width
        )
        
    def generate_tracking_attempts_panel(self, width: int) -> Panel:
        """Genera un panel con los intentos de rastreo detectados, mostrando solo los 4 más recientes."""
        content = []

        if not self.tracking_attempts:
            content.append(Text("No se han detectado intentos de rastreo...", style="dim"))
        else:
            for attempt in self.tracking_attempts[-4:]:
                src_ip = attempt["src_ip"]
                tracker_domain = attempt["tracker_domain"]
                full_dst_domain = attempt["full_dst_domain"]
                timestamp = time.strftime("%H:%M:%S", time.localtime(attempt["timestamp"]))

                content.append(Text(f"[{timestamp}] Desde ", style="dim") + 
                               Text(f"{src_ip}", style="bright_red") +
                               Text(f" -> Rastreador: ", style="bright_white") +
                               Text(f"{tracker_domain}", style="cyan") +
                               Text(f" ({full_dst_domain})", style="dim"))
        
        return Panel(
            Group(*content),
            title="[b]Intentos de Rastreo Web[/b]",
            border_style="magenta",
            width=width
        )

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
    parser.add_argument('--dns-verify-cert', action='store_true', help="Verifica certificados TLS en IPs no esperadas (Reduce falsos positivos).")
    parser.add_argument('--dns-verify-timeout', type=float, default=2.0, help="Timeout (s) para verificaciones TLS (default: 2.0).")
    parser.add_argument('--dns-verify-maxips', type=int, default=5, help="Max. IPs por respuesta a verificar activamente (default: 5).")
    parser.add_argument('-g', '--gui', action='store_true', help="Inicia la interfaz gráfica para visualizar archivos .pcap.")
    return parser.parse_args(argv)

class PcapViewerGUI:
    def __init__(self, root, base_dir: str):
        self.root = root
        self.base_dir = base_dir
        self.root.title("MITMGuard - Visor PCAP y Análisis de Detección")
        self.root.geometry("1400x900")

        self.inventory_manager = DeviceInventory(self.base_dir) 

        self.config_options = {
            "tshark_timeout": 120.0
        }

        self.current_pcap_file = None
        self.all_packets = []
        self.filtered_packets = []
        self.detailed_packets_data = []
        
        self.search_index_proto = "1.0"
        self.search_index_hex = "1.0"
        
        self.create_widgets()
        self.status_bar.config(text="Listo. Selecciona un archivo PCAP para empezar.")
        self.update_inventory_display()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        packet_tab = self._create_packet_analysis_tab(self.notebook)
        inventory_tab = self._create_inventory_tab(self.notebook)

        self.notebook.add(packet_tab, text="🔍 Análisis de Paquetes")
        self.notebook.add(inventory_tab, text="🚨 Inventario y Riesgo de Dispositivos")

        self.status_bar = ttk.Label(self.root, text="Listo", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        if hasattr(self, 'proto_details_text'):
             self.proto_details_text.tag_configure("found", background="yellow", foreground="black")
             self.hex_dump_text.tag_configure("found", background="yellow", foreground="black")

    def _create_packet_analysis_tab(self, parent):
        tab = tk.Frame(parent)

        top_frame = tk.Frame(tab)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        open_button = ttk.Button(top_frame, text="Abrir PCAP", command=self.on_file_select)
        open_button.pack(side=tk.LEFT, padx=(0, 5))

        filter_label = ttk.Label(top_frame, text="Filtro de Visualización (Wireshark):")
        filter_label.pack(side=tk.LEFT, padx=(5, 0))

        self.filter_entry = ttk.Entry(top_frame, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=5)

        apply_filter_button = ttk.Button(top_frame, text="Aplicar Filtro", command=self.on_apply_filter)
        apply_filter_button.pack(side=tk.LEFT, padx=5)
        
        export_filtered_button = ttk.Button(
            top_frame, 
            text="💾 Guardar PCAP Filtrado", 
            command=self.save_filtered_pcap
        )
        export_filtered_button.pack(side=tk.LEFT, padx=5)

        flow_button = ttk.Button(
            top_frame, 
            text="🔗 Filtrar por Flujo", 
            command=self.filter_by_flow
        )
        flow_button.pack(side=tk.LEFT, padx=5)

        search_label = ttk.Label(top_frame, text="Buscar:")
        search_label.pack(side=tk.LEFT, padx=(15, 0))

        self.search_entry = ttk.Entry(top_frame, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=5)

        search_button = ttk.Button(top_frame, text="Buscar", command=self.on_search)
        search_button.pack(side=tk.LEFT, padx=5)

        export_button = ttk.Button(top_frame, text="Exportar Datos", command=self.on_export)
        export_button.pack(side=tk.LEFT, padx=5)

        tree_frame = tk.Frame(tab)
        tree_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.packet_tree = ttk.Treeview(tree_frame, columns=("No.", "Time", "Source", "Destination", "Protocol", "Info"), show="headings")
        self.packet_tree.heading("No.", text="No.")
        self.packet_tree.heading("Time", text="Tiempo")
        self.packet_tree.heading("Source", text="Origen")
        self.packet_tree.heading("Destination", text="Destino")
        self.packet_tree.heading("Protocol", text="Protocolo")
        self.packet_tree.heading("Info", text="Información")

        self.packet_tree.column("No.", width=50, anchor=tk.W, stretch=False)
        self.packet_tree.column("Time", width=120, anchor=tk.W, stretch=False)
        self.packet_tree.column("Source", width=150, anchor=tk.W, stretch=False)
        self.packet_tree.column("Destination", width=150, anchor=tk.W, stretch=False)
        self.packet_tree.column("Protocol", width=80, anchor=tk.W, stretch=False)
        self.packet_tree.column("Info", width=500, anchor=tk.W, stretch=True)

        tree_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.pack(fill=tk.BOTH, expand=True)

        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        self.packet_tree.tag_configure('high_risk_packet', background='#FF9999', foreground='black') 
        self.packet_tree.tag_configure('medium_risk_packet', background='#FFCC99', foreground='black') 

        h_paned_window = ttk.PanedWindow(tab, orient=tk.HORIZONTAL)
        h_paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        details_frame = tk.Frame(h_paned_window, borderwidth=1, relief="sunken")
        h_paned_window.add(details_frame, weight=1)
        
        details_label = ttk.Label(details_frame, text="Detalles del Paquete (Protocolo)")
        details_label.pack(side=tk.TOP, fill=tk.X)
        self.proto_details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.proto_details_text.pack(fill=tk.BOTH, expand=True)

        hex_frame = tk.Frame(h_paned_window, borderwidth=1, relief="sunken")
        h_paned_window.add(hex_frame, weight=1)
        
        hex_label = ttk.Label(hex_frame, text="Volcado Hexadecimal (Contenido del Paquete)")
        hex_label.pack(side=tk.TOP, fill=tk.X)
        self.hex_dump_text = scrolledtext.ScrolledText(hex_frame, wrap=tk.WORD, state=tk.DISABLED, font=("Consolas", 9))
        self.hex_dump_text.pack(fill=tk.BOTH, expand=True)

        return tab

    def _create_inventory_tab(self, parent):
        tab = tk.Frame(parent)
        
        tree_frame = tk.Frame(tab)
        tree_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.device_tree = ttk.Treeview(tree_frame, 
            columns=("Key", "Name", "RiskScore", "Trusted", "LastSeen"), 
            show="headings"
        )
        self.device_tree.heading("Key", text="Clave IP/MAC")
        self.device_tree.heading("Name", text="Nombre de Usuario")
        self.device_tree.heading("RiskScore", text="Puntuación de Riesgo 🚨")
        self.device_tree.heading("Trusted", text="De Confianza")
        self.device_tree.heading("LastSeen", text="Última Vista (Hora Local)")

        self.device_tree.column("Key", width=150, anchor=tk.W, stretch=False)
        self.device_tree.column("Name", width=150, anchor=tk.W, stretch=False)
        self.device_tree.column("RiskScore", width=100, anchor=tk.CENTER, stretch=False)
        self.device_tree.column("Trusted", width=80, anchor=tk.CENTER, stretch=False)
        self.device_tree.column("LastSeen", width=200, anchor=tk.W, stretch=True)

        self.device_tree.tag_configure('high_risk', background='#FFCCCC', foreground='black') 
        self.device_tree.tag_configure('medium_risk', background='#FFFFCC', foreground='black') 
        self.device_tree.tag_configure('trusted_status', foreground='green', font=('TkDefaultFont', 9, 'bold'))

        tree_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.pack(fill=tk.BOTH, expand=True)

        self.device_tree.bind("<Button-3>", self.show_inventory_context_menu)

        management_frame = tk.Frame(tab)
        management_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        refresh_button = ttk.Button(management_frame, text="🔄 Actualizar Lista", command=self.update_inventory_display)
        refresh_button.pack(side=tk.LEFT, padx=5)

        rename_button = ttk.Button(management_frame, text="✍️ Renombrar Dispositivo", command=self.rename_device)
        rename_button.pack(side=tk.LEFT, padx=5)

        reset_risk_button = ttk.Button(management_frame, text="✅ Restablecer Riesgo", command=self.reset_risk_score)
        reset_risk_button.pack(side=tk.LEFT, padx=5)

        trust_button = ttk.Button(management_frame, text="⭐ Alternar Confianza", command=self.toggle_trust_status)
        trust_button.pack(side=tk.LEFT, padx=5)

        return tab
    
    def update_inventory_display(self):
        self.device_tree.delete(*self.device_tree.get_children())
        
        for key, info in self.inventory_manager.inventory.items():
            risk_score = info.get('risk_score', 0)
            
            tag_list = []
            if risk_score > 50: 
                tag_list.append('high_risk')
            elif risk_score > 10: 
                tag_list.append('medium_risk')
            
            if info.get('trusted', False):
                tag_list.append('trusted_status')

            last_seen_formatted = datetime.fromtimestamp(info.get('last_seen', time.time())).strftime("%Y-%m-%d %H:%M:%S")

            values = (
                key, 
                info.get('name', key), 
                risk_score, 
                "SÍ" if info.get('trusted', False) else "NO", 
                last_seen_formatted
            )
            
            self.device_tree.insert("", "end", values=values, tags=tuple(tag_list))
        
        self.status_bar.config(text=f"Inventario actualizado. Total de dispositivos: {len(self.inventory_manager.inventory)}")

    def _get_selected_inventory_key(self):
        selected_item = self.device_tree.focus()
        if not selected_item:
            messagebox.showwarning("Error de Selección", "Por favor, selecciona un dispositivo de la lista primero.")
            return None
        return self.device_tree.item(selected_item, 'values')[0]
        
    def rename_device(self):
        key = self._get_selected_inventory_key()
        if not key: return

        current_name = self.inventory_manager.get_device_info(key).get('name', key)
        new_name = simpledialog.askstring("Renombrar Dispositivo", f"Introduce el nuevo nombre para el dispositivo {key}:", initialvalue=current_name)

        if new_name and new_name.strip() and new_name.strip() != current_name:
            self.inventory_manager.set_device_name(key, new_name.strip())
            self.update_inventory_display()
            messagebox.showinfo("Éxito", f"Dispositivo {key} renombrado a '{new_name.strip()}'.")

    def reset_risk_score(self):
        key = self._get_selected_inventory_key()
        if not key: return

        if messagebox.askyesno("Confirmar Restablecimiento", f"¿Estás seguro de que quieres restablecer la puntuación de riesgo para {key}?"):
            info = self.inventory_manager.get_device_info(key)
            info['risk_score'] = 0
            self.inventory_manager.save_inventory()
            self.update_inventory_display()
            messagebox.showinfo("Éxito", f"La puntuación de riesgo para {key} se ha restablecido a 0.")

    def toggle_trust_status(self):
        key = self._get_selected_inventory_key()
        if not key: return
            
        info = self.inventory_manager.get_device_info(key)
        new_trust_status = not info.get('trusted', False)
        
        status_text = "Sí" if new_trust_status else "No"
        if messagebox.askyesno("Confirmar Estado de Confianza", f"¿Deseas establecer '{key}' como de confianza: {status_text}?"):
            info['trusted'] = new_trust_status
            self.inventory_manager.save_inventory()
            self.update_inventory_display()
            messagebox.showinfo("Éxito", f"El estado de confianza para {key} se estableció en: {status_text}.")

    def show_inventory_context_menu(self, event):
        self.device_tree.identify_row(event.y) 
        key = self._get_selected_inventory_key()
        if not key: return
        
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="✍️ Renombrar Dispositivo", command=self.rename_device)
        menu.add_command(label="✅ Restablecer Riesgo", command=self.reset_risk_score)
        menu.add_command(label="⭐ Alternar Confianza", command=self.toggle_trust_status)
        
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def on_file_select(self):
        file_path = filedialog.askopenfilename(
            initialdir=self.base_dir,
            title="Selecciona un archivo PCAP",
            filetypes=(("Archivos PCAP", "*.pcap"), ("Todos los archivos", "*.*"))
        )
        if file_path:
            self.current_pcap_file = file_path

            try:
                self.status_bar.config(text=f"Cargando todos los paquetes Scapy de {os.path.basename(file_path)}...")
                self.root.update_idletasks()
                
                self.all_packets = rdpcap(file_path) 
                self.filtered_packets = list(self.all_packets)
                
                self.status_bar.config(text=f"Cargados {len(self.all_packets)} paquetes totales. Aplicando filtro de visualización...")
                self.root.update_idletasks()
                
            except Exception as e:
                messagebox.showerror("Error de Scapy", f"No se pudo cargar el PCAP con Scapy (requerido para filtro de flujo/exportación): {e}")
                self.all_packets = []
                self.filtered_packets = []
                return

            self.on_apply_filter()

    def on_apply_filter(self):
        if not self.current_pcap_file or not self.all_packets:
            messagebox.showinfo("Error", "Por favor, abre un archivo PCAP primero.")
            return

        display_filter = self.filter_entry.get().strip()
        
        self.status_bar.config(text=f"Aplicando filtro '{display_filter or 'ninguno'}'...")
        self.root.update_idletasks()

        try:
            self.load_packets(self.current_pcap_file, display_filter=display_filter)
            
            self.status_bar.config(text=f"Filtro aplicado. Mostrando {len(self.detailed_packets_data)} paquetes.")
        except Exception as e:
            messagebox.showerror("Error de Filtro", f"Fallo al aplicar el filtro: {e}")
            self.filtered_packets = []
            self.clear_packet_display()
            self.status_bar.config(text="Error al aplicar el filtro.")

    def filter_by_flow(self):
        selected_item = self.packet_tree.focus()
        if not selected_item:
            messagebox.showwarning("Filtro de Flujo", "Selecciona un paquete en la lista para filtrar por su flujo de conversación.")
            return

        frame_number_str = self.packet_tree.item(selected_item, 'values')[0]
        if not frame_number_str or not self.all_packets: 
            messagebox.showwarning("Filtro de Flujo", "No hay datos de paquete completo disponibles.")
            return

        try:
            original_packet_index_in_all = int(frame_number_str) - 1
            target_packet = self.all_packets[original_packet_index_in_all]
        except (ValueError, IndexError):
            messagebox.showwarning("Filtro de Flujo", "Error al localizar el paquete original para el análisis de flujo.")
            return

        src_ip = None
        dst_ip = None
        
        if target_packet.haslayer(IP):
            ip_layer = target_packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        elif target_packet.haslayer(IPv6):
            ip_layer = target_packet[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        
        if not (src_ip and dst_ip):
            messagebox.showwarning("Filtro de Flujo", "El paquete seleccionado no es un paquete IP (IPv4 o IPv6).")
            return

        proto_name = None
        
        if target_packet.haslayer(TCP):
            transport_layer = target_packet[TCP] 
            proto_name = "tcp"
        elif target_packet.haslayer(UDP):
            transport_layer = target_packet[UDP]
            proto_name = "udp"
        else:
            messagebox.showwarning("Filtro de Flujo", "El paquete seleccionado no pertenece a un flujo TCP o UDP.")
            return
            
        sport = transport_layer.sport
        dport = transport_layer.dport

        filter_string = (
            f"((ip.addr == {src_ip} and ip.addr == {dst_ip}) "
            f"and ({proto_name}.port == {sport} and {proto_name}.port == {dport}))"
        )

        self.filter_entry.delete(0, tk.END)
        self.filter_entry.insert(0, filter_string)
        self.on_apply_filter()
        
    def save_filtered_pcap(self):
        if not self.filtered_packets:
             messagebox.showinfo("Error de Exportación", "No hay paquetes filtrados o cargados para exportar.")
             return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")],
            title="Guardar PCAP Filtrado"
        )
        if file_path:
            try:
                wrpcap(file_path, self.filtered_packets)
                messagebox.showinfo("Éxito", f"PCAP filtrado guardado exitosamente en: {file_path}")
            except Exception as e:
                messagebox.showerror("Error de Escritura", f"No se pudo guardar el archivo PCAP: {e}")
    
    def on_search(self):
        query = self.search_entry.get().strip()
        if not query:
            return

        self.proto_details_text.tag_remove("found", "1.0", tk.END)
        self.hex_dump_text.tag_remove("found", "1.0", tk.END)
        self.search_index_proto = "1.0"
        self.search_index_hex = "1.0"

        found_in_proto = self._find_and_highlight(self.proto_details_text, query, self.search_index_proto)
        
        if not found_in_proto:
            self._find_and_highlight(self.hex_dump_text, query, self.search_index_hex)

    def _find_and_highlight(self, text_widget, query, start_index):
        text_widget.config(state=tk.NORMAL)
        text_widget.mark_set("matchStart", start_index)
        
        count_var = tk.StringVar()
        found_index = text_widget.search(query, "matchStart", stopindex=tk.END, count=count_var)
        
        if found_index:
            end_index = f"{found_index}+{len(query)}c"
            text_widget.tag_add("found", found_index, end_index)
            text_widget.see(found_index) 
            text_widget.config(state=tk.DISABLED)
            return True
        else:
            text_widget.config(state=tk.DISABLED)
            messagebox.showinfo("Búsqueda", f"No se encontraron coincidencias para '{query}'.")
            return False

    def clear_packet_display(self):
        self.packet_tree.delete(*self.packet_tree.get_children())
        
        self.detailed_packets_data = []

        self.proto_details_text.config(state=tk.NORMAL)
        self.proto_details_text.delete('1.0', tk.END)
        self.proto_details_text.config(state=tk.DISABLED)
        self.hex_dump_text.config(state=tk.NORMAL)
        self.hex_dump_text.delete('1.0', tk.END)
        self.hex_dump_text.config(state=tk.DISABLED)
        self.proto_details_text.tag_remove("found", "1.0", tk.END)
        self.hex_dump_text.tag_remove("found", "1.0", tk.END)

    def load_packets(self, file_path: str, display_filter: str = ""):
        self.clear_packet_display()
        self.status_bar.config(text=f"Cargando paquetes de '{os.path.basename(file_path)}' con filtro '{display_filter or 'ninguno'}'...") # Mensaje de carga de paquetes
        
        packet_count = 0 
        self.detailed_packets_data = [] 
        self.filtered_packets = []      
        tshark_frame_numbers = []

        try:
            tshark_cmd = [
                "tshark", "-r", file_path,
                "-T", "fields",
                "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.len", 
                "-e", "eth.src", "-e", "eth.dst", 
                "-e", "ip.src", "-e", "ipv6.src", "-e", "ip.dst", "-e", "ipv6.dst",
                "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
                "-e", "sctp.srcport", "-e", "sctp.dstport", 
                "-e", "frame.protocols",
                "-e", "http.request.method", "-e", "http.request.uri", "-e", "http.host", 
                "-e", "dns.qry.name", "-e", "dns.resp.name", "-e", "dns.resp.type", 
                "-e", "arp.opcode", "-e", "arp.src.hw_mac", "-e", "arp.dst.hw_mac",
                "-e", "arp.src.proto_ipv4",
                "-E", "separator=,", "-E", "header=n", "-E", "occurrence=f"
            ]
            
            if display_filter:
                tshark_cmd.extend(["-Y", display_filter])

            subprocess_kwargs = {
                'stdout': subprocess.PIPE,
                'stderr': subprocess.PIPE,
                'text': True,
                'encoding': 'utf-8',
                'errors': 'ignore'
            }

            if os.name == 'nt':
                subprocess_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            
            proc = subprocess.Popen(tshark_cmd, **subprocess_kwargs)
            stdout, stderr = proc.communicate(timeout=self.config_options["tshark_timeout"])
            
            if proc.returncode != 0 and stderr and not stdout:
                messagebox.showerror("Error de tshark", f"Filtro inválido o error al cargar paquetes: {stderr}")
                self.status_bar.config(text="Error al cargar paquetes.")
                return
            elif stderr:
                print(f"Advertencias de tshark al cargar paquetes: {stderr}")

            field_names = [
                "frame_number", "frame_time_epoch", "frame_length",
                "eth_src", "eth_dst", 
                "ip_src", "ipv6_src", "ip_dst", "ipv6_dst",
                "tcp_srcport", "tcp_dstport", "udp_srcport", "udp_dstport",
                "sctp_srcport", "sctp_dstport", 
                "frame_protocols",
                "http_request_method", "http.request.uri", "http_host",
                "dns_query_name", "dns_response_name", "dns_response_type", 
                "arp_opcode", "arp_src_hw", "arp_dst_hw", "arp_src_proto_ipv4"
            ]
            
            print(f"Número esperado de campos para el análisis: {len(field_names)}")

            for line in stdout.strip().split('\n'):
                if not line: continue
                try:
                    parts = [p.strip() for p in line.split(',')]

                    while len(parts) < len(field_names):
                        parts.append("")
                    if len(parts) > len(field_names):
                        parts = parts[:len(field_names)]
                    
                    packet_detail = dict(zip(field_names, parts))

                    frame_number = packet_detail.get("frame_number", "")
                    tshark_frame_numbers.append(int(frame_number))
                    
                    timestamp_epoch = float(packet_detail.get("frame_time_epoch", "0"))
                    dt_object = datetime.fromtimestamp(timestamp_epoch)
                    timestamp_formatted = dt_object.strftime("%H:%M:%S.%f")[:-3]
                    
                    src_ip = packet_detail.get("ip_src", "") or packet_detail.get("ipv6_src", "")
                    dst_ip = packet_detail.get("ip_dst", "") or packet_detail.get("ipv6_dst", "")
                    src_port = packet_detail.get("tcp_srcport", "") or packet_detail.get("udp_srcport", "") or packet_detail.get("sctp_srcport", "") or ""
                    dst_port = packet_detail.get("tcp_dstport", "") or packet_detail.get("udp_dstport", "") or packet_detail.get("sctp_dstport", "") or ""
                    
                    protocols_raw = packet_detail.get("frame_protocols", "")

                    proto, info = "DESCONOCIDO", protocols_raw

                    if packet_detail.get("http_request_method"):
                        proto, info = "HTTP", f"{packet_detail.get('http_request_method')} {packet_detail.get('http.request.uri')} (Host: {packet_detail.get('http_host')})"
                    elif packet_detail.get("dns_query_name") or packet_detail.get("dns_response_name"):
                        proto = "DNS"
                        info = f"Query: {packet_detail.get('dns_query_name')}" if packet_detail.get('dns_query_name') else f"Response: {packet_detail.get('dns_response_name')}"
                    elif packet_detail.get("arp_opcode"):
                        proto = "ARP"
                        info = f"Who has {packet_detail.get('arp_src_proto_ipv4')}? Tell {packet_detail.get('arp_src_hw')}" if packet_detail.get('arp_opcode') == '1' else f"{packet_detail.get('arp_src_proto_ipv4')} is at {packet_detail.get('arp_src_hw')}"
                    elif "tcp" in protocols_raw:
                        proto = "TCP"
                        info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    elif "udp" in protocols_raw:
                        proto = "UDP"
                        info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    elif "ip" in protocols_raw or "ipv6" in protocols_raw:
                        proto = "IP" if packet_detail.get("ip_src") else "IPv6"
                        info = f"{src_ip} -> {dst_ip}"
                    
                    self.packet_tree.insert("", "end", values=(frame_number, timestamp_formatted, src_ip, dst_ip, proto, info))
                    self.detailed_packets_data.append(packet_detail) 
                    packet_count += 1

                except (ValueError, IndexError) as e:
                    print(f"Error crítico de análisis en la línea de tshark: {e} - Línea: '{line}'")
                    continue

            self.filtered_packets = []
            if self.all_packets:
                for frame_num in tshark_frame_numbers:
                    scapy_index = frame_num - 1 
                    if 0 <= scapy_index < len(self.all_packets):
                        self.filtered_packets.append(self.all_packets[scapy_index])
                    else:
                        print(f"Advertencia: tshark informó el marco {frame_num} pero está fuera del rango para all_packets.")

        except FileNotFoundError:
            messagebox.showerror("Error", "No se encontró tshark. Asegúrese de que Wireshark esté instalado y de que tshark esté en su PATH.")
            self.status_bar.config(text="Error: tshark no encontrado.")
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            messagebox.showerror("Error Tshark", "Tshark tomó demasiado tiempo para responder y fue terminado.")
            self.status_bar.config(text="Error: tiempo de espera de tshark.")
        except Exception as e:
            messagebox.showerror("Error", f"Se produjo un error inesperado al cargar paquetes: {e}")
            self.status_bar.config(text="Error inesperado al cargar paquetes.")
        
        finally:
            self.status_bar.config(text=f"Se cargaron {packet_count} paquetes en la pantalla. Se filtraron paquetes Scapy.: {len(self.filtered_packets)}")
            self.root.update_idletasks()

    def on_export(self):
        if not self.detailed_packets_data:
            messagebox.showinfo("Exportar", "No hay paquetes para exportar.")
            return

        file_path = filedialog.asksaveasfilename(
            initialdir=self.base_dir,
            title="Exportar Paquetes",
            defaultextension=".jsonl",
            filetypes=(
                ("Archivos JSONL", "*.jsonl"),
                ("Archivos CSV", "*.csv"),
                ("Archivos de texto", "*.txt"),
                ("Todos los archivos", "*.*")
            )
        )

        if not file_path:
            return

        try:
            if file_path.lower().endswith('.jsonl'):
                self._export_to_jsonl(file_path, self.detailed_packets_data)
            elif file_path.lower().endswith('.csv'):
                columns = list(self.detailed_packets_data[0].keys()) if self.detailed_packets_data else []
                self._export_to_csv(file_path, self.detailed_packets_data, columns)
            elif file_path.lower().endswith('.txt'):
                self._export_to_text(file_path, self.detailed_packets_data)
            else:
                messagebox.showerror("Error de Exportación", "Formato de archivo seleccionado no soportado.")
                return

            messagebox.showinfo("Exportación Exitosa", f"Paquetes exportados exitosamente a {os.path.basename(file_path)}")
            self.status_bar.config(text=f"Exportado a {os.path.basename(file_path)}")

        except Exception as e:
            messagebox.showerror("Error de Exportación", f"Ocurrió un error durante la exportación: {e}")
            self.status_bar.config(text="Fallo la exportación.")

    def _export_to_csv(self, file_path, data, columns):
        import csv
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            if not data: return
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            writer.writerows(data)

    def _export_to_jsonl(self, file_path, data):
        import json
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in data:
                f.write(json.dumps(item) + '\n')

    def _export_to_text(self, file_path, data):
        import json
        with open(file_path, 'w', encoding='utf-8') as f:
            for item in data:
                f.write(json.dumps(item, indent=2) + '\n---\n')
    
    def on_packet_select(self, event):
        selected_item = self.packet_tree.focus()
        if not selected_item: return
        
        frame_number = self.packet_tree.item(selected_item, 'values')[0]
        self.status_bar.config(text=f"Mostrando detalles para el paquete {frame_number}...")
        self.get_packet_details(self.current_pcap_file, frame_number)

    def get_packet_details(self, file_path, frame_number):
        self.proto_details_text.config(state=tk.NORMAL)
        self.hex_dump_text.config(state=tk.NORMAL)
        self.proto_details_text.delete('1.0', tk.END)
        self.hex_dump_text.delete('1.0', tk.END)
        self.proto_details_text.tag_remove("found", "1.0", tk.END) 
        self.hex_dump_text.tag_remove("found", "1.0", tk.END) 
        
        try:
            tshark_cmd = ["tshark", "-r", file_path, "-T", "text", "-V", "-x", "-Y", f"frame.number == {frame_number}"]
            
            subprocess_kwargs = {
                'stdout': subprocess.PIPE,
                'stderr': subprocess.PIPE,
                'text': True,
                'encoding': 'utf-8',
                'errors': 'ignore'
            }

            if os.name == 'nt':
                subprocess_kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
            
            proc = subprocess.Popen(tshark_cmd, **subprocess_kwargs)
            stdout, stderr = proc.communicate(timeout=10)
            
            if proc.returncode != 0 and stderr:
                messagebox.showerror("Error de tshark", f"No se pudieron recuperar los detalles del paquete: {stderr}")
                return

            protocol_details = []
            hex_dump = []
            hex_section_started = False
            hex_line_pattern = re.compile(r"^[0-9a-fA-F]{4}\s{1,}(?:[0-9a-fA-F]{2}\s{1,}){1,}")

            for line in stdout.splitlines():
                if not line.strip():
                    if hex_section_started:
                        hex_dump.append(line)
                    else:
                        protocol_details.append(line)
                    continue

                if not hex_section_started and hex_line_pattern.match(line):
                    hex_section_started = True
                
                if hex_section_started:
                    hex_dump.append(line)
                else:
                    protocol_details.append(line)

            self.proto_details_text.insert(tk.END, "\n".join(protocol_details).strip())
            self.hex_dump_text.insert(tk.END, "\n".join(hex_dump).strip())

        except FileNotFoundError:
            messagebox.showerror("Error", "tshark no encontrado. Asegúrese de que Wireshark esté instalado y tshark en su PATH.")
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            messagebox.showerror("Error de tshark", "tshark tardó demasiado en responder y fue terminado.")
            self.status_bar.config(text="Error: tiempo de espera de tshark agotado.")
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error inesperado al mostrar detalles: {e}")
            self.status_bar.config(text="Error inesperado al mostrar detalles.")
        finally:
            self.proto_details_text.config(state=tk.DISABLED)
            self.hex_dump_text.config(state=tk.DISABLED)

def main(argv: Optional[List[str]] = None):
    args = parse_args(argv)
    
    if args.gui:
        if not os.path.exists(BASE_DIR):
            os.makedirs(BASE_DIR)
        
        root = tk.Tk()
        app = PcapViewerGUI(root, BASE_DIR)
        root.mainloop()
        return

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
