import argparse
import subprocess
import sys
import os
import glob

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def clean_generated_files(base_path: str):
    """Elimina archivos generados por la herramienta (logs, pcaps, jsonl, diagramas)."""
    targets = [
        os.path.join(base_path, "alerts.jsonl"),
        os.path.join(base_path, "mitm_debug.log"),
        os.path.join(base_path, "mitm_detector.log"),
        os.path.join(base_path, "network_diagram.png"),
    ]

    targets.extend(glob.glob(os.path.join(base_path, "*.pcap")))

    removed, not_found = [], []
    for f in targets:
        if os.path.exists(f):
            try:
                os.remove(f)
                removed.append(f)
            except Exception as e:
                print(f"[!] No se pudo borrar {f}: {e}")
        else:
            not_found.append(f)

    print("[*] Archivos eliminados:")
    for f in removed:
        print(f"   - {os.path.basename(f)}")
    if not removed:
        print("   (ninguno encontrado)")

def parse_args():
    parser = argparse.ArgumentParser(description="Launcher for MITMGuard: Man-in-the-Middle Attack Detector and Countermeasures")
    parser.add_argument('-i', '--interface', required=True, help="Network interface to monitor (e.g., eth0, wlan0).")
    parser.add_argument('-c', '--countermeasures', action='store_true', help="Activates countermeasures (ARP/ND).")
    parser.add_argument('-p', '--passive', action='store_true', help="Passive mode (detection only).")
    parser.add_argument('--trusted-ips', type=str, help="Comma-separated trusted IPs.")
    parser.add_argument('-t', '--test', action='store_true', help="Test mode: simulates DNS spoofing.")
    parser.add_argument('--json-out', type=str, default="alerts.jsonl", help="JSONL file to export alerts.")
    parser.add_argument('--no-active-scan', action='store_true', help="Disables periodic active scanning.")
    parser.add_argument('--log-only', action='store_true', help="Do not start Rich UI; log only.")
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'], help="Logging level.")
    parser.add_argument('-L', '--lang', default="en", choices=["en", "es"], help="Set language for messages (en, es).")
    parser.add_argument('-C', '--clean', action='store_true', help="Borra archivos generados (logs, pcaps, jsonl, diagramas) y sale")
    parser.add_argument('--dns-verify-cert', action='store_true', help="Verify TLS certificates for unexpected DNS IPs.")
    parser.add_argument('--dns-verify-timeout', type=float, default=2.0, help="Timeout (s) for DNS verification lookups.")
    parser.add_argument('--dns-verify-maxips', type=int, default=5, help="Max IPs to verify per DNS response.")
    # AÑADIR ESTA LÍNEA
    parser.add_argument('--gui', action='store_true', help="Lanza la interfaz gráfica de usuario (GUI).")
    return parser.parse_args()

def main():
    args = parse_args()
    
    if args.clean:
        clean_generated_files(BASE_DIR)
        sys.exit(0)

    lang_to_file = {
        "es": "MITMGuard_Spanish.py",
        "en": "MITMGuard_English.py"
    }
    
    script_to_run = lang_to_file.get(args.lang)

    if not script_to_run:
        print(f"Error: Unsupported language: {args.lang}", file=sys.stderr)
        sys.exit(1)
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))

    full_script_path = os.path.join(base_path, script_to_run)

    if base_path not in sys.path:
        sys.path.insert(0, base_path)

    try:
        module_name = script_to_run.replace('.py', '')

        import importlib.util
        spec = importlib.util.spec_from_file_location(module_name, full_script_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        target_args = []
        if args.interface:
            target_args.extend(["--interface", args.interface])
        if args.countermeasures:
            target_args.append("--countermeasures")
        if args.passive:
            target_args.append("--passive")
        if args.trusted_ips:
            target_args.extend(["--trusted-ips", args.trusted_ips])
        if args.test:
            target_args.append("--test")
        if args.json_out:
            target_args.extend(["--json-out", args.json_out])
        if args.no_active_scan:
            target_args.append("--no-active-scan")
        if args.log_only:
            target_args.append("--log-only")
        if args.log_level:
            target_args.extend(["--log-level", args.log_level])
        if args.dns_verify_cert:
            target_args.append("--dns-verify-cert")
        if args.dns_verify_timeout:
            target_args.extend(["--dns-verify-timeout", str(args.dns_verify_timeout)])
        if args.dns_verify_maxips:
            target_args.extend(["--dns-verify-maxips", str(args.dns_verify_maxips)])
        # AÑADIR ESTA LÍNEA
        if args.gui:
            target_args.append("--gui")
        original_sys_argv = sys.argv[:]
        sys.argv = ['_placeholder_script_name_'] + target_args
        
        module.main()
        
    except KeyboardInterrupt:
        print("\nLauncher caught KeyboardInterrupt. Exiting gracefully.", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"An unexpected error occurred while loading or running {script_to_run}: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        sys.argv = original_sys_argv


if __name__ == "__main__":
    main()
