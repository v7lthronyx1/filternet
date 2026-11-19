import os
import pathlib
import shutil
from .net_os import flush_dns_cache, get_os

MANAGED_HOSTS = ("deb.debian.org", "security.debian.org", "pypi.org")
DEFAULT_APT_CONF = pathlib.Path("/etc/apt/apt.conf.d/99-filternet-ipv4")


def default_hosts_path():
    if get_os() == "windows":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        return pathlib.Path(root) / "System32" / "drivers" / "etc" / "hosts"
    return pathlib.Path("/etc/hosts")


def is_managed_line(line, hostnames=MANAGED_HOSTS):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    parts = stripped.split()
    return len(parts) >= 2 and parts[1] in hostnames


def read_managed_pins(hosts_path=None):
    path = pathlib.Path(hosts_path) if hosts_path else default_hosts_path()
    pins = []
    if not path.exists():
        return pins
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if is_managed_line(line):
            parts = line.strip().split()
            pins.append((parts[1], parts[0]))
    return pins


def apply_pins(mappings, hosts_path=None, install_apt_ipv4=True, apt_conf_path=None):
    is_system = hosts_path is None
    path = pathlib.Path(hosts_path) if hosts_path else default_hosts_path()
    bak = path.with_name(path.name + ".filternet.bak")
    if path.exists() and not bak.exists():
        shutil.copy2(path, bak)
    existing = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    kept = [ln for ln in existing if not is_managed_line(ln, hostnames=tuple(mappings.keys()) + MANAGED_HOSTS)]
    for host, ip in mappings.items():
        kept.append(f"{ip} {host}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")

    apt_written = False
    if install_apt_ipv4 and get_os() == "linux":
        apt_path = pathlib.Path(apt_conf_path) if apt_conf_path else DEFAULT_APT_CONF
        if apt_path.parent.exists():
            apt_path.write_text('Acquire::ForceIPv4 "true";\n', encoding="utf-8")
            apt_written = True

    if is_system:
        flush_dns_cache()
    return {"hosts_path": str(path), "apt_ipv4_written": apt_written}


def revert_pins(hosts_path=None, apt_conf_path=None):
    is_system = hosts_path is None
    path = pathlib.Path(hosts_path) if hosts_path else default_hosts_path()
    removed = 0
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="replace").splitlines()
        kept = []
        for ln in existing:
            if is_managed_line(ln):
                removed += 1
            else:
                kept.append(ln)
        path.write_text(("\n".join(kept) + "\n") if kept else "", encoding="utf-8")

    apt_removed = False
    if get_os() == "linux":
        apt_path = pathlib.Path(apt_conf_path) if apt_conf_path else DEFAULT_APT_CONF
        if apt_path.exists():
            apt_path.unlink()
            apt_removed = True

    if is_system:
        flush_dns_cache()
    return {"hosts_path": str(path), "removed": removed, "apt_ipv4_removed": apt_removed}
