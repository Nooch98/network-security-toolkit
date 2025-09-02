from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
import io
from typing import Dict, List, Optional, Set, Tuple

from colorama import init as colorama_init
from rich.console import Console
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
)
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP
from scapy.layers.l2 import getmacbyip
from scapy.layers.http import HTTPRequest
from scapy.layers.dhcp import DHCP
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6ND_NS

import dns.resolver

# Inicializar colorama
colorama_init(autoreset=True)


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

        # UI
        self.console = Console()
        self.alerts: List[Tuple[str, str]] = []
        self.packet_count = 0
        self.ui_lock = threading.Lock()
        self.recent_malicious_packet = None

        # Info de red
        try:
            self.my_ip = get_if_addr(self.interface)
            self.my_mac = get_if_hwaddr(self.interface)
        except Exception:
            self.my_ip = None
            self.my_mac = None

        self.my_ipv6_local = None
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

        self.dns_cache = DNSCache(["8.8.8.8", "1.1.1.1", "9.9.9.9"])

        self._setup_logging(log_level)
        self._warn_if_not_root()

    # -------------------- setup --------------------
    def _warn_if_not_root(self):
        try:
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                self.console.print(Panel("[bold yellow]Advertencia:[/] Ejecuta como root/admin para obtener captura/emit correctamente."))
        except Exception:
            pass

    def _setup_logging(self, level: str):
        lvl = getattr(logging, (level or 'INFO').upper(), logging.INFO)
        logging.basicConfig(
            level=lvl,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='mitm_detector.log',
            filemode='a',
        )
        console_handler = logging.StreamHandler()
        console_handler.setLevel(lvl)
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(console_handler)

    # -------------------- logging & alerts --------------------
    def _write_json_event(self, payload: dict):
        if not self.json_out:
            return
        try:
            with open(self.json_out, 'a', encoding='utf-8') as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "")
        except Exception as e:
            logging.error(f"Error escribiendo evento JSON: {e}")

    def log_malicious_packet(self, packet, alert_type: str):
        try:
            filename = f"{alert_type.lower()}_alerts.pcap"
            wrpcap(filename, packet, append=True)
            logging.warning(f"[!] Paquete malicioso guardado en '{filename}'.")
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
            self.console.log("[bold cyan]Descubriendo dispositivos en la red...[/bold cyan]")
        if self.active_scan:
            self.discover_network_devices_ipv4()
            self.discover_network_devices_ipv6()
        self.discover_system_dns()
        with self.ui_lock:
            self.console.log("[bold green]Descubrimiento completado. Iniciando monitoreo...[/bold green]")

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
                        logging.info(f"[+] Contramedida ARP: {self.gateway_ip_v4} -> {self.gateway_mac_v4}")

                    if self.gateway_ip_v6 and self.gateway_mac_v6:
                        nd_packet = Ether(dst=self.gateway_mac_v6) / IPv6(src=self.gateway_ip_v6, dst="ff02::1") / ICMPv6ND_NA(tgt=self.gateway_ip_v6, S=1, R=1, O=1)
                        sendp(nd_packet, iface=self.interface, verbose=False)
                        logging.info(f"[+] Contramedida ND: {self.gateway_ip_v6} -> {self.gateway_mac_v6}")
                except Exception as e:
                    logging.debug(f"Error contramedidas: {e}")
            if self.stop_event.wait(3):
                break

    # -------------------- monitoreo ARP --------------------
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
                        )
                except Exception as e:
                    logging.debug(f"Error monitoreando caché ARP: {e}")
            if self.stop_event.wait(10):
                break

    # -------------------- test mode --------------------
    def test_dns_spoofing(self):
        with self.ui_lock:
            self.console.log("[*] [bold cyan]Iniciando simulación de DNS Spoofing...[/bold cyan]")
        if not self.my_ip or not self.gateway_ip_v4 or not self.my_mac or not self.gateway_mac_v4:
            with self.ui_lock:
                self.console.log("No se pudo obtener IP/MAC o gateway. No se puede ejecutar la prueba.")
            return
        test_domain = "test.com"
        test_ip = "1.2.3.4"
        dns_query_packet = Ether(src=self.my_mac, dst=self.gateway_mac_v4)/IP(src=self.my_ip, dst=self.gateway_ip_v4)/UDP(sport=55555, dport=53)/DNS(id=1234, qr=0, rd=1, qd=DNSQR(qname=test_domain, qtype="A"))
        dns_spoofed_packet = Ether(src=self.gateway_mac_v4, dst=self.my_mac)/IP(src=self.gateway_ip_v4, dst=self.my_ip)/UDP(sport=53, dport=55555)/DNS(id=1234, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=test_domain, qtype="A"), an=DNSRR(rrname=test_domain, ttl=600, rdata=test_ip))
        for pkt in (dns_query_packet, dns_spoofed_packet):
            self.handle_packet(pkt)
        with self.ui_lock:
            self.console.log("[*] [bold green]Prueba finalizada.[/bold green]")
        self.stop()

    # -------------------- manejadores --------------------
    def handle_arp(self, packet):
        try:
            arp_op = packet[ARP].op
            arp_src_ip = packet[ARP].psrc
            arp_src_mac = packet[ARP].hwsrc
            if arp_op == 2:
                if self.gateway_ip_v4 and arp_src_ip == self.gateway_ip_v4 and self.gateway_mac_v4 and arp_src_mac != self.gateway_mac_v4:
                    self.log_alert("ARP_SPOOFING", f"La IP {arp_src_ip} cambió de MAC", f"Original: {self.gateway_mac_v4}, Sospechosa: {arp_src_mac}", packet=packet)
            if arp_src_ip not in self.arp_table or self.arp_table[arp_src_ip] != arp_src_mac:
                with self.ui_lock:
                    self.arp_table[arp_src_ip] = arp_src_mac
                    self.console.log(f"Nueva entrada ARP: {arp_src_ip} -> {arp_src_mac}")
        except Exception:
            pass

    def handle_ipv6_nd(self, packet):
        try:
            if packet.haslayer(ICMPv6ND_NA):
                ip = packet[IPv6].src
                mac = packet[Ether].src
                if ip not in self.trusted_ips:
                    self.trusted_ips.add(ip)
                    logging.info(f"[*] Dispositivo IPv6 confiable: {ip} -> {mac}")
            if packet.haslayer(ICMPv6ND_RA):
                router_ip = packet[IPv6].src
                if router_ip not in self.trusted_ips:
                    self.trusted_ips.add(router_ip)
                    self.gateway_ip_v6 = router_ip
                    self.gateway_mac_v6 = packet[Ether].src
                    logging.info(f"[*] Gateway IPv6 descubierto: {router_ip}")
            if packet.haslayer(ICMPv6ND_NA) or packet.haslayer(ICMPv6ND_NS):
                ip = packet[IPv6].src
                mac = packet[Ether].src
                if self.gateway_ip_v6 and ip == self.gateway_ip_v6 and self.gateway_mac_v6 and mac != self.gateway_mac_v6:
                    self.log_alert("ICMPv6_SPOOFING", f"IPv6 {ip} cambió de MAC", f"Original: {self.gateway_mac_v6}, Sospechosa: {mac}", packet=packet)
                if ip not in self.neighbor_table or self.neighbor_table[ip] != mac:
                    with self.ui_lock:
                        self.neighbor_table[ip] = mac
                        self.console.log(f"Nueva entrada IPv6 ND: {ip} -> {mac}")
        except Exception:
            pass

    def check_dns_query(self, packet):
        try:
            if packet.haslayer(DNS) and packet[DNS].qr == 0:
                self.dns_queries[packet[DNS].id] = packet[DNS][DNSQR].qname
        except Exception:
            pass

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
                with self.ui_lock:
                    self.console.log(f"[*] Ignorando consulta local: {query_name}")
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

    def handle_packet(self, packet):
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
            logging.debug(f"Error procesando paquete: {e}")

    # -------------------- UI --------------------
    def generate_layout(self):
        with self.ui_lock:
            status_panel = Panel(
                f"[bold white]Estado:[/] {'[bold green]Activo[/]' if self.active else '[bold red]Detenido[/]'}\n"
                f"[bold white]Interfaz:[/] {self.interface}\n"
                f"[bold white]Gateway IPv4:[/] {self.gateway_ip_v4} ({self.gateway_mac_v4})\n"
                f"[bold white]Paquetes procesados:[/] {self.packet_count}\n",
                title="Estado de la Detección",
            )
            devices_table = Table(title="Dispositivos de la Red")
            devices_table.add_column("IP", style="cyan")
            devices_table.add_column("MAC", style="magenta")
            for ip, mac in self.arp_table.items():
                devices_table.add_row(ip, mac)
            for ip, mac in self.neighbor_table.items():
                devices_table.add_row(ip, mac)
            alerts_panel_content = ""
            for timestamp, alert in self.alerts:
                alerts_panel_content += f"[bold red]{timestamp}[/] - [bold yellow]{alert}[/]\n"
            alerts_panel = Panel(alerts_panel_content, title="Alertas de Seguridad")
            panels = [status_panel, devices_table, alerts_panel]
            if self.recent_malicious_packet:
                packet_io = io.StringIO()
                original_stdout = sys.stdout
                sys.stdout = packet_io
                try:
                    self.recent_malicious_packet.show()
                finally:
                    sys.stdout = original_stdout
                packet_dump = packet_io.getvalue()
                syntax = Syntax(packet_dump, "python", theme="monokai", line_numbers=False)
                packet_panel = Panel(syntax, title="Detalles del Paquete Malicioso")
                panels.append(packet_panel)
        return Columns(panels)

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
            self.console.log("[bold yellow]Interrumpido por el usuario[/bold yellow]")
        finally:
            self.stop()
            for t in threads:
                t.join(timeout=2)

    def stop(self):
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
