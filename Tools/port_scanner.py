#!/usr/bin/env python3
"""
port_scanner.py — TCP port scanner with banner grabbing and service detection.

Portfolio project: demonstrates socket programming, threading, and structured
output for security tooling. Part of cybersecurity-portfolio/tools/.

Usage:
    python port_scanner.py <target> [options]

Examples:
    python port_scanner.py scanme.nmap.org
    python port_scanner.py 192.168.1.1 --ports 1-1024
    python port_scanner.py example.com --ports 22,80,443,8080 --threads 100
    python port_scanner.py 10.0.0.1 --ports 1-65535 --timeout 0.5 --json
"""

import argparse
import json
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ── Common service fingerprints ──────────────────────────────────────────────

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Banners to send to elicit a response from common services
BANNER_PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n",
    21: None,   # FTP sends banner on connect
    22: None,   # SSH sends banner on connect
    25: None,   # SMTP sends banner on connect
}

print_lock = threading.Lock()


# ── Core scanner ─────────────────────────────────────────────────────────────

def grab_banner(sock: socket.socket, port: int, target: str, timeout: float) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        sock.settimeout(timeout)
        probe = BANNER_PROBES.get(port)

        if probe is not None:
            sock.send(probe.replace(b"{target}", target.encode()))

        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        # Truncate and clean up multi-line banners
        first_line = banner.split("\n")[0][:80]
        return first_line
    except Exception:
        return ""


def scan_port(target: str, port: int, timeout: float) -> dict | None:
    """
    Attempt a TCP connection to target:port.
    Returns a result dict if open, None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

            if result == 0:
                service = COMMON_SERVICES.get(port, "unknown")
                banner = grab_banner(sock, port, target, timeout)
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                }
    except socket.gaierror:
        # DNS resolution failure — let the caller handle it
        raise
    except OSError:
        pass

    return None


def resolve_target(target: str) -> str:
    """Resolve hostname to IP, exit cleanly on failure."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror as e:
        print(f"[!] Could not resolve '{target}': {e}")
        sys.exit(1)


def parse_ports(port_spec: str) -> list[int]:
    """
    Parse a port spec like '1-1024', '22,80,443', or '1-100,443,8080'.
    """
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    invalid = [p for p in ports if not (1 <= p <= 65535)]
    if invalid:
        print(f"[!] Invalid port(s): {invalid}")
        sys.exit(1)

    return sorted(ports)


# ── Output formatters ─────────────────────────────────────────────────────────

def print_result(result: dict) -> None:
    """Print a single open port result to stdout."""
    banner_str = f"  └─ {result['banner']}" if result["banner"] else ""
    with print_lock:
        print(
            f"  {result['port']:<6} open   {result['service']:<12}"
            + (f"\n{banner_str}" if banner_str else "")
        )


def build_report(target: str, ip: str, ports_scanned: list[int],
                 open_ports: list[dict], elapsed: float) -> dict:
    """Build a structured JSON-serializable report."""
    return {
        "scan": {
            "target": target,
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "ports_scanned": len(ports_scanned),
            "elapsed_seconds": round(elapsed, 2),
        },
        "results": {
            "open_count": len(open_ports),
            "open_ports": open_ports,
        },
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TCP port scanner with banner grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument(
        "--ports", "-p",
        default="1-1024",
        help="Ports to scan. Range (1-1024), list (22,80,443), or combo. Default: 1-1024",
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=200,
        help="Max concurrent threads (default: 200)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    args = parser.parse_args()

    target = args.target
    ip = resolve_target(target)
    ports = parse_ports(args.ports)
    start_time = datetime.utcnow()

    if not args.json:
        print(f"\n{'─'*55}")
        print(f"  Target   : {target} ({ip})")
        print(f"  Ports    : {len(ports)} ({args.ports})")
        print(f"  Threads  : {args.threads}")
        print(f"  Timeout  : {args.timeout}s")
        print(f"  Started  : {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"{'─'*55}\n")
        print(f"  {'PORT':<6} {'STATE':<7} {'SERVICE':<12}")
        print(f"  {'─'*4:<6} {'─'*5:<7} {'─'*7:<12}")

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, args.timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                    if not args.json:
                        print_result(result)
            except socket.gaierror:
                pass  # Already handled in resolve_target
            except Exception as e:
                port = futures[future]
                with print_lock:
                    print(f"  [!] Error on port {port}: {e}", file=sys.stderr)

    elapsed = (datetime.utcnow() - start_time).total_seconds()
    open_ports.sort(key=lambda r: r["port"])

    if args.json:
        report = build_report(target, ip, ports, open_ports, elapsed)
        print(json.dumps(report, indent=2))
    else:
        print(f"\n{'─'*55}")
        print(f"  Scan complete in {elapsed:.2f}s")
        print(f"  Open ports: {len(open_ports)} / {len(ports)} scanned")
        print(f"{'─'*55}\n")

        if not open_ports:
            print("  No open ports found.\n")
        else:
            # Security notes for common risky services
            risky = {p["port"] for p in open_ports}
            warnings = []
            if 23 in risky:
                warnings.append("  ⚠  Port 23 (Telnet) — plaintext protocol, should be disabled")
            if 21 in risky:
                warnings.append("  ⚠  Port 21 (FTP) — plaintext auth, prefer SFTP/SCP")
            if 3389 in risky:
                warnings.append("  ⚠  Port 3389 (RDP) — high-value brute force target")
            if 6379 in risky:
                warnings.append("  ⚠  Port 6379 (Redis) — often misconfigured without auth")
            if 27017 in risky:
                warnings.append("  ⚠  Port 27017 (MongoDB) — check for unauthenticated access")

            if warnings:
                print("  Security Notes:")
                print("\n".join(warnings))
                print()


if __name__ == "__main__":
    main()
