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

# Inicializar colorama para que funcione en Windows
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
        """Obtiene la dirección IPv6 Link-Local para la interfaz especificada."""
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
        """Configura el sistema de logging para consola y archivo."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            filename='mitm_detector.log',
            filemode='a'
        )

    def log_malicious_packet(self, packet, alert_type):
        """
        Guarda el paquete que causó la alerta en un archivo .pcap para análisis posterior.
        """
        filename = f"{alert_type.lower()}_alerts.pcap"
        wrpcap(filename, packet, append=True)
        logging.warning(f"[!] Paquete malicioso registrado en '{filename}'.")

    def log_alert(self, alert_type, message, details, packet=None):
        """Muestra una alerta en la consola (UI), la registra y guarda el paquete si es proporcionado."""
        alert_text = f"[{alert_type}] {message} -> {details}"
        with self.ui_lock:
            self.alerts.insert(0, (time.strftime("%H:%M:%S"), alert_text))
            self.alerts = self.alerts[:10]
        
        logging.critical(f"ALERTA: {alert_type} - {message} -> {details}")
        
        if packet:
            self.log_malicious_packet(packet, alert_type)
            self.recent_malicious_packet = packet

    def discover_system_dns(self):
        """Lee los servidores DNS directamente de la configuración del sistema operativo."""
        try:
            resolver = dns.resolver.Resolver()
            for server in resolver.nameservers:
                if server not in self.trusted_ips:
                    self.trusted_ips.add(server)
                    logging.info(f"[*] Servidor DNS legítimo añadido de la configuración del sistema: {server}")
        except Exception as e:
            logging.error(f"Error al descubrir DNS del sistema: {e}")

    def discover_network_devices(self):
        """Realiza un escaneo pasivo y activo para descubrir dispositivos en la red y los añade a la lista de confianza."""
        with self.ui_lock:
            self.console.log(f"[bold cyan]Descubriendo dispositivos en la red...[/bold cyan]")
        
        if self.gateway_ip_v4:
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{self.gateway_ip_v4}/24"), timeout=2, iface=self.interface, verbose=False)
                for _, received in ans:
                    ip = received[ARP].psrc
                    mac = received[Ether].src
                    if ip not in self.trusted_ips:
                        self.trusted_ips.add(ip)
                        logging.info(f"[*] Dispositivo legítimo descubierto y añadido a IPs de confianza: {ip} -> {mac}")
            except Exception as e:
                logging.error(f"Error al escanear IPv4: {e}")
        
        try:
            ans, _ = srp(Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_RA(), timeout=2, iface=self.interface, verbose=False)
            for _, received in ans:
                router_ip = received[IPv6].src
                router_mac = received[Ether].src
                if router_ip not in self.trusted_ips:
                    self.trusted_ips.add(router_ip)
                    self.gateway_ip_v6 = router_ip
                    self.gateway_mac_v6 = router_mac
                    logging.info(f"[*] Router IPv6 legítimo descubierto y añadido a IPs de confianza: {router_ip} -> {router_mac}")

            ans, _ = srp(Ether(dst="33:33:00:00:00:01")/IPv6(dst="ff02::1")/ICMPv6ND_NS(), timeout=2, iface=self.interface, verbose=False)
            for _, received in ans:
                ip = received[IPv6].src
                mac = received[Ether].src
                if ip not in self.trusted_ips and ip != self.my_ipv6_local and ip != self.gateway_ip_v6:
                    self.trusted_ips.add(ip)
                    logging.info(f"[*] Dispositivo IPv6 legítimo descubierto y añadido a IPs de confianza: {ip} -> {mac}")
        except Exception as e:
            logging.error(f"Error al escanear IPv6: {e}")
        
        self.discover_system_dns()
        with self.ui_lock:
            self.console.log(f"[bold green]Descubrimiento de red completado. Iniciando monitoreo...[/bold green]")

    def run_periodic_scans(self):
        """Ejecuta escaneos de red cada 5 minutos para mantener actualizada la tabla de confianza."""
        while self.active and not self.passive_mode and not self.test_mode:
            time.sleep(300)
            self.discover_network_devices()

    def run_active_countermeasures(self):
        """Envía paquetes ARP y ND gratuitos para restablecer las tablas de la red."""
        while self.active:
            if not self.passive_mode and not self.test_mode:
                try:
                    if self.gateway_ip_v4 and self.gateway_mac_v4:
                        arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=self.gateway_ip_v4, hwsrc=self.gateway_mac_v4, pdst=self.my_ip)
                        sendp(arp_packet, iface=self.interface, verbose=False)
                        logging.info(f"[+] Enviando contramedidas ARP. Router: {self.gateway_ip_v4} tiene la MAC: {self.gateway_mac_v4}")
                    
                    if self.gateway_ip_v6 and self.gateway_mac_v6:
                        nd_packet = Ether(dst=self.gateway_mac_v6) / IPv6(src=self.gateway_ip_v6, dst="ff02::1") / ICMPv6ND_NA(tgt=self.gateway_ip_v6, S=1, R=1, O=1)
                        sendp(nd_packet, iface=self.interface, verbose=False)
                        logging.info(f"[+] Enviando contramedidas ND. Router IPv6: {self.gateway_ip_v6} tiene la MAC: {self.gateway_mac_v6}")

                except Exception as e:
                    logging.error(f"Error al enviar contramedidas: {e}")
            
            time.sleep(3)

    def monitor_arp_cache(self):
        """
        Revisa la caché ARP del sistema de forma proactiva para detectar
        envenenamiento incluso sin recibir paquetes.
        """
        while self.active:
            if not self.test_mode and self.gateway_ip_v4 and self.gateway_mac_v4:
                try:
                    current_gateway_mac = getmacbyip(self.gateway_ip_v4)
                    if current_gateway_mac and current_gateway_mac != self.gateway_mac_v4:
                        self.log_alert(
                            "ARP_SPOOFING_PROACTIVO",
                            f"La MAC del router en la caché ARP del sistema ha cambiado de forma inesperada.",
                            f"MAC original: {self.gateway_mac_v4}, MAC sospechosa: {current_gateway_mac}",
                            packet=None 
                        )
                except Exception as e:
                    logging.error(f"Error al monitorear la caché ARP: {e}")
            time.sleep(10)
    
    def test_dns_spoofing(self):
        """Crea una lista de paquetes de prueba y los procesa para simular el ataque."""
        with self.ui_lock:
            self.console.log(f"[*] [bold cyan]Iniciando simulación de ataque de DNS Spoofing...[/bold cyan]")
        
        if not self.my_ip or not self.gateway_ip_v4:
            with self.ui_lock:
                 self.console.log("No se pudo obtener la IP y/o el gateway. No se puede ejecutar la prueba de DNS Spoofing.")
            return

        test_domain = "test.com"
        test_ip = "1.2.3.4"
        
        test_packets = []
        
        # Paquete de consulta DNS legítimo
        dns_query_packet = (
            Ether(src=self.my_mac, dst=self.gateway_mac_v4) /
            IP(src=self.my_ip, dst=self.gateway_ip_v4) /
            UDP(sport=55555, dport=53) /
            DNS(id=1234, qr=0, rd=1, qd=DNSQR(qname=test_domain, qtype="A"))
        )
        
        # Paquete de respuesta DNS malicioso
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
            self.console.log("[*] Procesando paquetes de prueba...")
        for pkt in test_packets:
            self.handle_packet(pkt)
            
        with self.ui_lock:
            self.console.log(f"[*] [bold green]Prueba de ataque finalizada. Verificando resultado...[/bold green]")
        self.stop()

    def handle_arp(self, packet):
        """Maneja los paquetes ARP para detectar y mitigar spoofing."""
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
                        f"La IP {arp_src_ip} ha cambiado de MAC.",
                        f"MAC original: {self.gateway_mac_v4}, MAC sospechosa: {arp_src_mac}",
                        packet=packet
                    )
                
            if arp_src_ip not in self.arp_table or self.arp_table[arp_src_ip] != arp_src_mac:
                with self.ui_lock:
                    self.arp_table[arp_src_ip] = arp_src_mac
                    self.console.log(f"Nueva entrada ARP: IP {arp_src_ip} -> MAC {arp_src_mac}")
        
        except IndexError:
            pass

    def handle_ipv6_nd(self, packet):
        """Maneja los paquetes ICMPv6 ND para detectar spoofing en IPv6."""
        if not self.active:
            return
        
        try:
            if packet.haslayer(ICMPv6ND_NA):
                target_ip = packet[IPv6].src
                target_mac = packet[Ether].src
                if target_ip not in self.trusted_ips:
                    self.trusted_ips.add(target_ip)
                    logging.info(f"[*] Dispositivo IPv6 legítimo descubierto y añadido a IPs de confianza: {target_ip} -> {target_mac}")
                
            if packet.haslayer(ICMPv6ND_RA):
                router_ip = packet[IPv6].src
                if router_ip not in self.trusted_ips:
                    self.trusted_ips.add(router_ip)
                    logging.info(f"[*] Gateway IPv6 descubierto y añadido a IPs de confianza: {router_ip}")
                    self.gateway_ip_v6 = router_ip
                    self.gateway_mac_v6 = packet[Ether].src
            
            if packet.haslayer(ICMPv6ND_NA) or packet.haslayer(ICMPv6ND_NS):
                target_ip = packet[IPv6].src
                target_mac = packet[Ether].src
                
                if self.gateway_ip_v6 and target_ip == self.gateway_ip_v6 and target_mac != self.gateway_mac_v6:
                     self.log_alert(
                         "ICMPv6_SPOOFING",
                         f"La IP IPv6 {target_ip} ha cambiado de MAC.",
                         f"MAC original: {self.gateway_mac_v6}, MAC sospechosa: {target_mac}",
                         packet=packet
                     )
                
                if target_ip not in self.neighbor_table or self.neighbor_table[target_ip] != target_mac:
                    with self.ui_lock:
                        self.neighbor_table[target_ip] = target_mac
                        self.console.log(f"Nueva entrada IPv6 ND: IP {target_ip} -> MAC {target_mac}")
        except IndexError:
            pass

    def check_dns_query(self, packet):
        """Almacena las consultas DNS para verificar las respuestas más tarde."""
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
        """Verifica si las respuestas DNS son legítimas o spoofeadas."""
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
                            self.console.log(f"[*] Consulta local ignorada: {query_name}")
                        if packet[DNS].id in self.dns_queries:
                             del self.dns_queries[packet[DNS].id]
                        return

                    if not packet_resolved_ips:
                        self.log_alert(
                            "DNS_RESPUESTA_VACIA",
                            f"Respuesta DNS vacía para '{query_name}'.",
                            "Posible error de captura, no se considera un ataque."
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
                        expected_ips_str = ', '.join(set(valid_ips)) if valid_ips else "No hay IPs legítimas"
                        
                        self.log_alert(
                            "DNS_SPOOFING",
                            f"La respuesta DNS para '{query_name}' es inválida.",
                            f"IPs esperadas: {expected_ips_str}, IPs recibidas: {packet_resolved_ips}",
                            packet=packet
                        )
                    
                    if packet[DNS].id in self.dns_queries:
                        del self.dns_queries[packet[DNS].id]

        except IndexError:
            pass
        except Exception as e:
            logging.error(f"Error en check_dns_response: {e}")

    def check_for_sslstrip(self, packet):
        """Verifica si hay solicitudes HTTP para sitios que deberían ser HTTPS."""
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
                            f"Detectada una conexión HTTP no segura a un sitio web sensible.",
                            f"Dominio: {host}, IP de destino: {dest_ip}. Esto podría ser un ataque de SSLstrip.",
                            packet=packet
                        )
                    if host in self.dns_responses:
                        del self.dns_responses[host]
        except IndexError:
            pass
        except Exception as e:
            logging.error(f"Error en check_for_sslstrip: {e}")

    def handle_dhcp_packet(self, packet):
        if not self.active:
            return

        try:
            if packet.haslayer(DHCP) and packet[DHCP].options and packet[DHCP].options[0] and packet[DHCP].options[0][1] == 2:
                src_ip = packet[IP].src
                if src_ip != self.gateway_ip_v4 and src_ip not in self.trusted_ips:
                    self.log_alert(
                        "DHCP_SPOOFING",
                        f"Detectado un servidor DHCP no autorizado.",
                        f"IP del servidor sospechoso: {src_ip}, MAC: {packet[Ether].src}",
                        packet=packet
                    )
        except IndexError:
            pass
        except Exception as e:
            logging.error(f"Error en handle_dhcp_packet: {e}")
            
    def handle_packet(self, packet):
        """Función principal para manejar todos los paquetes."""
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
            logging.error(f"Error procesando paquete: {e}")
    
    def generate_layout(self):
        """Genera el layout de la UI para Rich."""
        with self.ui_lock:
            status_panel = Panel(
                f"[bold white]Estado:[/] [bold green]Activo[/]\n"
                f"[bold white]Interfaz:[/] {self.interface}\n"
                f"[bold white]Gateway IPv4:[/] {self.gateway_ip_v4} ({self.gateway_mac_v4})\n"
                f"[bold white]Paquetes procesados:[/] {self.packet_count}",
                title="Estado de la Detección"
            )

            trusted_devices_table = Table(title="Dispositivos de la Red")
            trusted_devices_table.add_column("IP", style="cyan")
            trusted_devices_table.add_column("MAC", style="magenta")
            
            for ip, mac in self.arp_table.items():
                trusted_devices_table.add_row(ip, mac)
            for ip, mac in self.neighbor_table.items():
                trusted_devices_table.add_row(ip, mac)

            alerts_panel_content = ""
            for timestamp, alert in self.alerts:
                alerts_panel_content += f"[bold red]{timestamp}[/] - [bold yellow]{alert}[/]\n"
            
            alerts_panel = Panel(Text(alerts_panel_content, justify="left"), title="Alertas de Seguridad")

            panels = [status_panel, trusted_devices_table, alerts_panel]

            if self.recent_malicious_packet:
                packet_io = io.StringIO()
                original_stdout = sys.stdout
                sys.stdout = packet_io
                
                self.recent_malicious_packet.show()
                
                sys.stdout = original_stdout
                
                packet_dump = packet_io.getvalue()
                
                syntax = Syntax(packet_dump, "python", theme="monokai", line_numbers=False)
                packet_panel = Panel(syntax, title="Detalles del Paquete Malicioso")
                panels.append(packet_panel)

        return Columns(panels)

    def start_ui(self):
        """Inicia el hilo de la UI interactiva."""
        with Live(self.generate_layout(), screen=True, auto_refresh=True, vertical_overflow="visible") as live:
            while self.active:
                live.update(self.generate_layout())
                time.sleep(0.5)
            if self.test_mode:
                time.sleep(2)

    def start_passive_detection(self):
        """Inicia el sniffer de forma pasiva."""
        try:
            sniff(prn=self.handle_packet, iface=self.interface, store=0)
        except Exception as e:
            logging.error(f"Error al iniciar el sniffer: {e}")
            self.stop()
            
    def run(self):
        """Ejecuta la herramienta de detección."""
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
    parser = argparse.ArgumentParser(description="Herramienta de detección y mitigación de ataques MitM en IPv4 e IPv6.")
    parser.add_argument('-i', '--interface', required=True, help="Interfaz de red a monitorear (ej. eth0, Wi-Fi).")
    parser.add_argument('-c', '--countermeasures', action='store_true', help="Activa las contramedidas activas para mitigar el ataque.")
    parser.add_argument('-p', '--passive', action='store_true', help="Ejecuta el script en modo pasivo (solo detección sin mitigación).")
    parser.add_argument('--trusted-ips', type=str, help="Lista de IPs confiables, separadas por comas. (ej. 192.168.1.39)")
    parser.add_argument('-t', '--test', action='store_true', help="Activa el modo de prueba para simular un ataque de DNS Spoofing localmente.")
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
