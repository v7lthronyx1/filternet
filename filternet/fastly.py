import concurrent.futures
from .net_os import http_fetch_pinned

DEBIAN_POPS = ("146.75.118.132", "151.101.130.132", "151.101.66.132")
SECURITY_POPS = ("151.101.194.132", "151.101.130.132", "146.75.118.132")
PYPI_POPS = ("151.101.0.223", "151.101.64.223", "151.101.130.132")


def probe_fastly_debian_range(ip, rng="0-20479", source_ip=None, timeout=6.0, bind_iface=None):
    r = http_fetch_pinned(
        ip,
        "deb.debian.org",
        "/debian/dists/stable/Release",
        port=80,
        https=False,
        headers={"Range": f"bytes={rng}"},
        timeout=timeout,
        source_ip=source_ip,
        bind_iface=bind_iface,
    )
    return {
        "rc": 0 if r["ok"] else 28,
        "http_code": r["http_code"],
        "bytes": r["bytes"],
        "mbps": r["mbps"],
        "err": r["err"],
    }


def run_fastly_checks(source_ip=None, bind_iface=None):
    tasks = [
        ("151.101.18.132_4k", "151.101.18.132", "0-4095"),
        ("151.101.18.132_20k", "151.101.18.132", "0-20479"),
        ("146.75.118.132_20k", "146.75.118.132", "0-20479"),
        ("151.101.130.132_20k", "151.101.130.132", "0-20479"),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {k: ex.submit(probe_fastly_debian_range, ip, rng, source_ip, 6.0, bind_iface) for k, ip, rng in tasks}
        return {k: fut.result() for k, fut in futs.items()}


def pick_healthy_mirrors(source_ip=None, bind_iface=None):
    deb_ip = None
    for ip in DEBIAN_POPS:
        res = probe_fastly_debian_range(ip, rng="0-20479", source_ip=source_ip, bind_iface=bind_iface)
        if res["http_code"] in (200, 206) and res["bytes"] >= 20000:
            deb_ip = ip
            break
    if not deb_ip:
        return None

    sec_ip = SECURITY_POPS[0]
    for ip in SECURITY_POPS:
        r = http_fetch_pinned(ip, "security.debian.org", "/debian-security/dists/stable-security/Release", port=443, https=True, timeout=6.0, source_ip=source_ip, bind_iface=bind_iface)
        if r["http_code"] in (200, 301, 302):
            sec_ip = ip
            break

    pypi_ip = PYPI_POPS[0]
    for ip in PYPI_POPS:
        r = http_fetch_pinned(ip, "pypi.org", "/", port=443, https=True, timeout=6.0, source_ip=source_ip, bind_iface=bind_iface)
        if r["http_code"] in (200, 301, 302):
            pypi_ip = ip
            break

    return {
        "deb.debian.org": deb_ip,
        "security.debian.org": sec_ip,
        "pypi.org": pypi_ip,
    }
