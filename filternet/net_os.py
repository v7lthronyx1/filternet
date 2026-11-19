import ctypes
import http.client
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import time


def get_os():
    sys_name = platform.system().lower()
    if sys_name.startswith("win"):
        return "windows"
    if sys_name == "darwin":
        return "macos"
    return "linux"


def is_admin():
    if get_os() == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def resolve_source_ip(iface_or_ip):
    if not iface_or_ip:
        return None
    try:
        ipaddress.IPv4Address(iface_or_ip)
        return iface_or_ip
    except ValueError:
        pass
    os_name = get_os()
    if os_name == "linux":
        p = subprocess.run(["ip", "-4", "-j", "addr", "show", "dev", iface_or_ip], capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            for item in json.loads(p.stdout):
                for info in item.get("addr_info", []):
                    if info.get("family") == "inet" and info.get("local"):
                        return info["local"]
    elif os_name == "macos":
        p = subprocess.run(["ipconfig", "getifaddr", iface_or_ip], capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    elif os_name == "windows":
        p = subprocess.run(["netsh", "interface", "ip", "show", "addresses", f"name={iface_or_ip}"], capture_output=True, text=True)
        if p.returncode == 0:
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", p.stdout):
                if not ip.startswith(("255.", "0.")):
                    return ip
    raise SystemExit(f"Could not resolve IPv4 address for interface: {iface_or_ip}")


def detect_local_dns_servers():
    os_name = get_os()
    servers = []
    if os_name == "linux":
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] not in servers:
                        servers.append(parts[1])
        except OSError:
            pass
    elif os_name == "macos" and shutil.which("scutil"):
        p = subprocess.run(["scutil", "--dns"], capture_output=True, text=True)
        if p.returncode == 0:
            for m in re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", p.stdout):
                if m not in servers:
                    servers.append(m)
    elif os_name == "windows" and shutil.which("netsh"):
        p = subprocess.run(["netsh", "interface", "ip", "show", "dnsservers"], capture_output=True, text=True)
        if p.returncode == 0:
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", p.stdout):
                if ip not in servers:
                    servers.append(ip)
    return servers


def detect_active_interfaces():
    os_name = get_os()
    if os_name == "linux" and shutil.which("ip"):
        p = subprocess.run(["ip", "-4", "-br", "addr"], capture_output=True, text=True)
        if p.returncode == 0:
            lines = [ln for ln in p.stdout.splitlines() if ln.strip() and not ln.startswith(("lo ", "br-", "docker", "veth", "lxcbr"))]
            return lines
    elif os_name == "macos" and shutil.which("ifconfig"):
        p = subprocess.run(["ifconfig"], capture_output=True, text=True)
        if p.returncode == 0:
            out = []
            cur = None
            for ln in p.stdout.splitlines():
                if not ln.startswith(("\t", " ")) and ":" in ln:
                    cur = ln.split(":", 1)[0]
                elif cur and "inet " in ln and "127.0.0.1" not in ln:
                    ip = ln.strip().split()[1]
                    out.append(f"{cur}: {ip}")
            return out
    elif os_name == "windows" and shutil.which("netsh"):
        p = subprocess.run(["netsh", "interface", "ip", "show", "config"], capture_output=True, text=True)
        if p.returncode == 0:
            return [ln.strip() for ln in p.stdout.splitlines() if "IP Address" in ln or "Configuration for interface" in ln]
    return []


def pmtu_check(target="1.1.1.1", payload_bytes=1472, source_ip=None):
    os_name = get_os()
    if os_name == "windows":
        cmd = ["ping", "-n", "1", "-f", "-l", str(payload_bytes), "-w", "2000"]
        if source_ip:
            cmd += ["-S", source_ip]
    elif os_name == "macos":
        cmd = ["ping", "-n", "-D", "-s", str(payload_bytes), "-c", "1", "-W", "2000"]
        if source_ip:
            cmd += ["-S", source_ip]
    else:
        cmd = ["ping", "-n", "-M", "do", "-s", str(payload_bytes), "-c", "1", "-W", "2"]
        if source_ip:
            cmd += ["-I", source_ip]
    cmd.append(target)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return p.returncode == 0 and "ttl=" in p.stdout.lower()
    except Exception:
        return False


def flush_dns_cache():
    os_name = get_os()
    try:
        if os_name == "windows" and shutil.which("ipconfig"):
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=5)
            return True
        if os_name == "macos":
            if shutil.which("dscacheutil"):
                subprocess.run(["dscacheutil", "-flushcache"], capture_output=True, text=True, timeout=5)
            if shutil.which("killall"):
                subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, text=True, timeout=5)
            return True
        if os_name == "linux" and shutil.which("resolvectl"):
            subprocess.run(["resolvectl", "flush-caches"], capture_output=True, text=True, timeout=5)
            return True
    except Exception:
        pass
    return False


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port=80, connect_ip=None, **kwargs):
        super().__init__(host, port=port, **kwargs)
        self._connect_ip = connect_ip or host

    def connect(self):
        self.sock = socket.create_connection((self._connect_ip, self.port), self.timeout, self.source_address)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=443, connect_ip=None, sni_host=None, verify_ssl=True, **kwargs):
        ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
        super().__init__(host, port=port, context=ctx, **kwargs)
        self._connect_ip = connect_ip or host
        self._sni_host = sni_host or host

    def connect(self):
        sock = socket.create_connection((self._connect_ip, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni_host)


def http_fetch_pinned(ip, host_hdr, path, port=None, https=True, headers=None, timeout=5.0, source_ip=None, verify_ssl=True):
    port = port or (443 if https else 80)
    src = (source_ip, 0) if source_ip else None
    req_headers = {"Host": host_hdr, "User-Agent": "FilterNet/1.0", "Connection": "close"}
    if headers:
        req_headers.update(headers)
    conn = None
    body_chunks = []
    t0 = time.monotonic()
    try:
        if https:
            conn = PinnedHTTPSConnection(host_hdr, port=port, connect_ip=ip, sni_host=host_hdr, verify_ssl=verify_ssl, timeout=timeout, source_address=src)
        else:
            conn = PinnedHTTPConnection(host_hdr, port=port, connect_ip=ip, timeout=timeout, source_address=src)
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        status = resp.status
        while True:
            chunk = resp.read(2048)
            if not chunk:
                break
            body_chunks.append(chunk)
        elapsed = max(0.001, time.monotonic() - t0)
        data = b"".join(body_chunks)
        return {
            "ok": 200 <= status < 400,
            "http_code": status,
            "bytes": len(data),
            "mbps": round((len(data) * 8.0) / (elapsed * 1_000_000.0), 2),
            "elapsed_s": round(elapsed, 3),
            "body": data,
            "err": None,
        }
    except Exception as e:
        elapsed = max(0.001, time.monotonic() - t0)
        partial = b"".join(body_chunks)
        return {
            "ok": False,
            "http_code": 0,
            "bytes": len(partial),
            "mbps": round((len(partial) * 8.0) / (elapsed * 1_000_000.0), 2),
            "elapsed_s": round(elapsed, 3),
            "body": partial,
            "err": f"{type(e).__name__}: {e}",
        }
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
