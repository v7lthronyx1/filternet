import argparse
import concurrent.futures
import json
import pathlib
import platform
import sys
from . import APP_NAME, AUTHOR, BRAND, __version__
from .dns_raw import classify_dns_verdict, pick_local_stub, query_dns_raw, run_dns_checks
from .dpi import doh_probe, run_cloud_checks, run_dpi_checks, run_protocol_checks
from .fastly import DEBIAN_POPS, pick_healthy_mirrors, probe_fastly_debian_range, run_fastly_checks
from .hosts_mgr import apply_pins, default_hosts_path, read_managed_pins, revert_pins
from .net_os import detect_active_interfaces, detect_local_dns_servers, get_os, is_admin, pmtu_check, resolve_bind_target
from .wg_conf import prepare_wg_config

DNSCRYPT_CROSSPLATFORM_TOML = """listen_addresses = ['127.0.0.1:53']
server_names = ['cf1', 'cf2', 'gg1', 'gg2']
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = false
doh_servers = true
require_dnssec = false
require_nolog = false
require_nofilter = false
ignore_system_dns = true
netprobe_timeout = 0
timeout = 2500
keepalive = 5
lb_strategy = 'wp2'
cache = true
cache_size = 4096
cache_min_ttl = 60
cache_max_ttl = 600
cache_neg_min_ttl = 30
cache_neg_max_ttl = 60
bootstrap_resolvers = ['1.1.1.1:53', '8.8.8.8:53']

[static]
  [static.'cf1']
  stamp = 'sdns://AgcAAAAAAAAABzEuMS4xLjEABzEuMS4xLjEKL2Rucy1xdWVyeQ'
  [static.'cf2']
  stamp = 'sdns://AgcAAAAAAAAABzEuMC4wLjEABzEuMC4wLjEKL2Rucy1xdWVyeQ'
  [static.'gg1']
  stamp = 'sdns://AgcAAAAAAAAABzguOC44LjgABzguOC44LjgKL2Rucy1xdWVyeQ'
  [static.'gg2']
  stamp = 'sdns://AgcAAAAAAAAABzguOC40LjQABzguOC40LjQKL2Rucy1xdWVyeQ'
"""

DNSCRYPT_SYSTEMD_TOML = DNSCRYPT_CROSSPLATFORM_TOML.replace("listen_addresses = ['127.0.0.1:53']", "listen_addresses = []", 1)


def run_probe_suite(source_ip=None, quick=False, bind_iface=None):
    report = {"os": get_os(), "source_ip": source_ip or "default", "dns": {}, "protocols": {}, "dpi": {}, "fastly": {}, "cloud": {}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_dns = ex.submit(run_dns_checks, source_ip, bind_iface)
        f_proto = ex.submit(run_protocol_checks, source_ip, bind_iface)
        f_dpi = ex.submit(run_dpi_checks, source_ip, bind_iface)
        f_fastly = ex.submit(run_fastly_checks, source_ip, bind_iface)
        f_cloud = ex.submit(run_cloud_checks, source_ip, bind_iface) if not quick else None
        report["dns"] = f_dns.result()
        report["protocols"] = f_proto.result()
        report["dpi"] = f_dpi.result()
        report["fastly"] = f_fastly.result()
        if f_cloud is not None:
            report["cloud"] = f_cloud.result()
    return report


def print_probe_summary(rep):
    print(f"{APP_NAME} v{__version__} ({BRAND}) — Probe ({rep['os']}, source: {rep['source_ip']})")
    print("\n[1] DNS Hijacking, Port 5353 & HTTPS RR Stripping")
    for k, v in rep["dns"].items():
        if "https_rr" in k:
            status = f"OK (HTTPS_RR={v['https_rr']})" if v["ok"] and v["https_rr"] > 0 else ("STRIPPED (HTTPS_RR=0)" if v["ok"] else v["error"])
        else:
            status = classify_dns_verdict(v)
        print(f"  {k:<26}: {status}")

    p = rep["protocols"]
    print("\n[2] Encrypted DNS, Ports, NTP & PMTU")
    print(f"  portquiz 443 / 853 / 51820 : {p['portquiz_443']['ok']} / {p['portquiz_853']['ok']} / {p['portquiz_51820']['ok']}")
    print(f"  DoT 853 (1.1.1.1 / AdGuard): {p['dot_1111']['tls_ok']} ({p['dot_1111']['err'] or 'OK'}) / {p['dot_adguard']['tls_ok']} ({p['dot_adguard']['err'] or 'OK'})")
    print(f"  DoH (bare-IP 1.1.1.1)      : {p['doh_ip_1111']['ok']} ({p['doh_ip_1111'].get('http_code') or p['doh_ip_1111'].get('err')})")
    print(f"  DoH (domain cloudflare-dns): {p['doh_domain_cf']['ok']} ({p['doh_domain_cf'].get('http_code') or p['doh_domain_cf'].get('err')})")
    print(f"  NTP (Google / Cloudflare)  : {p['ntp_google']['ok']} / {p['ntp_cloudflare']['ok']}")
    print(f"  PMTU 1500B (1472+28)       : {p['pmtu_1500_ok']}")

    d = rep["dpi"]
    print("\n[3] DPI Synthetic SNI, Geo-Block Separation & 2-Byte Evasion")
    print(f"  Synthetic 404 Hetzner/Vultr: {d['synthetic_hetzner_404']['outcome']} / {d['synthetic_vultr_404']['outcome']} (ctrl: {d['synthetic_hetzner_ctrl']['outcome']})")
    print(f"  HTTP 80 NSV2 Check (404)   : {d['http_nsv2_404']['block_sig'] or d['http_nsv2_404']['status'] or d['http_nsv2_404']['error']}")
    print(f"  x.com normal / ech_grease  : {d['x_normal']['outcome']} / {d['x_ech_grease']['outcome']}")
    print(f"  x.com split_2b / rec_split2: {d['x_split_2b']['outcome']} / {d['x_rec_split_2']['outcome']}")
    print(f"  DO Spaces normal / split_2b: {d['do_spaces_normal']['outcome']} / {d['do_spaces_split_2b']['outcome']}")
    print(f"  cloudflare.com TLS / HTTPS : {d['cloudflare_tls']['outcome']} / HTTP {d['cloudflare_https'].get('status') or d['cloudflare_https'].get('error')}")

    f = rep["fastly"]
    print("\n[4] Fastly deb.debian.org Stall Check (5552B Threshold)")
    print(f"  151.101.18.132 (0-4095)    : rc={f['151.101.18.132_4k']['rc']} bytes={f['151.101.18.132_4k']['bytes']}")
    print(f"  151.101.18.132 (0-20479)   : rc={f['151.101.18.132_20k']['rc']} bytes={f['151.101.18.132_20k']['bytes']}")
    print(f"  146.75.118.132 (0-20479)   : rc={f['146.75.118.132_20k']['rc']} bytes={f['146.75.118.132_20k']['bytes']} ({f['146.75.118.132_20k']['mbps']} Mbps)")
    print(f"  151.101.130.132 (0-20479)  : rc={f['151.101.130.132_20k']['rc']} bytes={f['151.101.130.132_20k']['bytes']} ({f['151.101.130.132_20k']['mbps']} Mbps)")

    if rep["cloud"]:
        print("\n[5] Cloud & VPS Reachability")
        for label, res in rep["cloud"].items():
            print(f"  {label:<26}: {res['outcome']} ({res['tls_ms'] or res['tcp_ms'] or '-'} ms)")

    tips = summarize_findings(probe_rep=rep)
    print("\n[What This Means]")
    for t in tips:
        print(f"  - {t}")


def summarize_findings(doc_rep=None, probe_rep=None):
    tips = []
    if doc_rep:
        ext_v = classify_dns_verdict(doc_rep["udp53_8844_probe"])
        if ext_v.startswith(("SINKHOLE", "FORCED_SAFESEARCH", "PRIVATE_HIJACK")):
            tips.append("Plain DNS is being altered by your network. Use IP-only DoH via: filternet dns-config")
        if doc_rep["doh_ip_1111"]["ok"] and not doc_rep["doh_domain_cf"]["ok"]:
            tips.append("Domain DoH (cloudflare-dns.com) is blocked while bare-IP DoH (1.1.1.1) works.")
        f = doc_rep["fastly"]
        if f["151.101.18.132_20k"]["bytes"] < 20000 and f["146.75.118.132_20k"]["bytes"] >= 20000:
            tips.append("Fastly node 151.101.18.132 stalls mid-download (breaks apt/pip). Fix with: filternet hosts-pin apply")
        if not doc_rep["pmtu_1500_ok"]:
            tips.append("1500B unfragmented packets failed (normal inside a VPN tunnel; set WireGuard MTU = 1280).")

    if probe_rep:
        dns = probe_rep["dns"]
        hijacked = any(
            classify_dns_verdict(dns[k]).startswith(("SINKHOLE", "FORCED_SAFESEARCH", "PRIVATE_HIJACK"))
            for k in ("udp53_8844_x", "udp53_8844_google", "udp5353_opendns_x", "tcp5353_opendns_x")
            if k in dns
        )
        if hijacked:
            tips.append("Plain DNS is returning fake/filtered IPs (even on port 5353). Use IP-only DoH via: filternet dns-config")
        p = probe_rep["protocols"]
        if p["doh_ip_1111"]["ok"] and not p["doh_domain_cf"]["ok"]:
            tips.append("Domain-based encrypted DNS is blocked while bare-IP DoH (1.1.1.1) works cleanly.")
        d = probe_rep["dpi"]
        if not d["x_normal"]["ok"] and d["x_split_2b"]["ok"]:
            tips.append("Your ISP blocks sites by reading the domain name (SNI), and 2-byte splitting (split_2b) bypasses it.")
        elif not d["x_normal"]["ok"] and d.get("x_rec_split_2", {}).get("ok"):
            tips.append("Your ISP blocks sites by reading the domain name (SNI) and resets plain TCP 2-byte splits; TLS record splitting (rec_split_2) bypasses it.")
        if not d["synthetic_hetzner_404"]["ok"] and d["synthetic_hetzner_ctrl"]["ok"]:
            tips.append("Confirmed mid-path keyword filtering: even non-existent domains sent to a clean server were cut.")
        f = probe_rep["fastly"]
        if f["151.101.18.132_20k"]["bytes"] < 20000 and f["146.75.118.132_20k"]["bytes"] >= 20000:
            tips.append("Fastly node 151.101.18.132 stalled above ~5.5 KB. Fix downloads/updates with: filternet hosts-pin apply")
        c = probe_rep.get("cloud") or {}
        if c:
            ok_good = c.get("Hetzner-FSN1", {}).get("ok") or c.get("Vultr-FRA", {}).get("ok")
            bad_vps = [k for k in ("Linode-FRA", "DO-FRA-Pool", "OVH-Proof") if k in c and not c[k].get("ok")]
            if ok_good and bad_vps:
                tips.append(f"Cloud routing drops detected ({', '.join(bad_vps)}); Hetzner/Vultr paths are healthier.")

    if not tips:
        tips.append("No active filtering or Fastly download stalls detected on this connection.")
    return tips


def run_doctor(source_ip=None, bind_iface=None):
    stub = pick_local_stub()
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_stub = ex.submit(query_dns_raw, stub, "x.com", 1, 53, "udp", source_ip, 2.0, None if stub.startswith("127.") else bind_iface)
        f_ext = ex.submit(query_dns_raw, "8.8.4.4", "x.com", 1, 53, "udp", source_ip, 2.0, bind_iface)
        f_doh_ip = ex.submit(doh_probe, "1.1.1.1", "1.1.1.1", source_ip, 4.0, bind_iface)
        f_doh_dom = ex.submit(doh_probe, "104.16.248.249", "cloudflare-dns.com", source_ip, 4.0, bind_iface)
        f_fastly = ex.submit(run_fastly_checks, source_ip, bind_iface)
        f_pmtu = ex.submit(pmtu_check, "1.1.1.1", 1472, source_ip, bind_iface)
    return {
        "os": get_os(),
        "platform": platform.platform(),
        "admin": is_admin(),
        "interfaces": detect_active_interfaces(),
        "configured_dns": detect_local_dns_servers(),
        "local_stub": stub,
        "local_stub_probe": f_stub.result(),
        "udp53_8844_probe": f_ext.result(),
        "doh_ip_1111": f_doh_ip.result(),
        "doh_domain_cf": f_doh_dom.result(),
        "fastly": f_fastly.result(),
        "hosts_path": str(default_hosts_path()),
        "hosts_pins": read_managed_pins(),
        "pmtu_1500_ok": f_pmtu.result(),
    }


def cmd_probe(args):
    src_ip, bind_iface = resolve_bind_target(args.interface)
    rep = run_probe_suite(source_ip=src_ip, quick=args.quick, bind_iface=bind_iface)
    if args.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        print_probe_summary(rep)
    return 0


def cmd_doctor(args):
    src_ip, bind_iface = resolve_bind_target(args.interface)
    doc = run_doctor(source_ip=src_ip, bind_iface=bind_iface)
    if args.json:
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return 0
    print(f"{APP_NAME} v{__version__} ({BRAND}) — Doctor")
    print(f"OS / Admin       : {doc['os']} ({doc['platform']}) | admin={doc['admin']}")
    print(f"Configured DNS   : {', '.join(doc['configured_dns']) or 'none detected'}")
    print(f"Local Stub ({doc['local_stub']}): {classify_dns_verdict(doc['local_stub_probe'])}")
    print(f"UDP/53 @8.8.4.4  : {classify_dns_verdict(doc['udp53_8844_probe'])}")
    print(f"DoH IP / Domain  : 1.1.1.1={doc['doh_ip_1111']['ok']} | cloudflare-dns.com={doc['doh_domain_cf']['ok']}")
    print(f"PMTU 1500B       : {doc['pmtu_1500_ok']}")
    print(f"Hosts Pins       : {doc['hosts_pins'] or 'none'} ({doc['hosts_path']})")
    f = doc["fastly"]
    print(f"Fastly 151.101.18.132 (20KB): {f['151.101.18.132_20k']['bytes']} B | 146.75.118.132: {f['146.75.118.132_20k']['bytes']} B")
    if doc["interfaces"]:
        print("Interfaces:")
        for line in doc["interfaces"][:10]:
            print(f"  {line}")
    print("\n[What This Means]")
    for t in summarize_findings(doc_rep=doc):
        print(f"  - {t}")
    return 0


def cmd_hosts_pin(args):
    if args.action == "status":
        print(f"Hosts file: {default_hosts_path()}")
        pins = read_managed_pins()
        print("Active pins:", pins if pins else "None")
        for ip in ("151.101.18.132", *DEBIAN_POPS):
            res = probe_fastly_debian_range(ip, rng="0-20479")
            tag = "STALL" if ip == "151.101.18.132" and res["bytes"] < 20000 else ("HEALTHY" if res["bytes"] >= 20000 else "FAILED")
            print(f"  {ip:<16} -> HTTP {res['http_code']}, {res['bytes']} bytes ({tag})")
        return 0
    if args.action == "apply":
        if not is_admin():
            raise SystemExit("Administrator / root privileges required to update hosts file.")
        mappings = pick_healthy_mirrors()
        if not mappings:
            raise SystemExit("No healthy deb.debian.org Fastly POP passed the 20KB test.")
        res = apply_pins(mappings, install_apt_ipv4=not args.no_apt_ipv4)
        print(f"Applied Fastly pins to {res['hosts_path']}:")
        for host, ip in mappings.items():
            print(f"  {host} -> {ip}")
        return 0
    if args.action == "revert":
        if not is_admin():
            raise SystemExit("Administrator / root privileges required to update hosts file.")
        res = revert_pins()
        print(f"Removed {res['removed']} pin(s) from {res['hosts_path']}.")
        return 0
    return 1


def cmd_wg_prepare(args):
    in_path = pathlib.Path(args.input_conf).expanduser()
    if not in_path.is_file():
        raise SystemExit(f"Config not found: {in_path}")
    text = in_path.read_text(encoding="utf-8", errors="replace")
    res = prepare_wg_config(
        text,
        mtu=args.mtu,
        keepalive=args.keepalive,
        drop_dns=not args.keep_dns,
        custom_dns=args.dns,
    )
    if args.output:
        out_path = pathlib.Path(args.output).expanduser()
        out_path.write_text(res["text"], encoding="utf-8")
        print(f"Wrote optimized WireGuard config to {out_path}")
        if res["resolved_ips"]:
            print(f"Resolved {res['endpoint_host']} via bare-IP DoH -> {', '.join(res['resolved_ips'])}")
    else:
        sys.stdout.write(res["text"])
    return 0


def cmd_dns_config(args):
    target = args.target
    if target == "auto":
        target = "systemd" if get_os() == "linux" else "crossplatform"
    content = DNSCRYPT_SYSTEMD_TOML if target == "systemd" else DNSCRYPT_CROSSPLATFORM_TOML
    if args.output:
        out_path = pathlib.Path(args.output).expanduser()
        out_path.write_text(content, encoding="utf-8")
        print(f"Wrote {target} dnscrypt-proxy config to {out_path}")
    else:
        sys.stdout.write(content)
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="filternet", description=f"{APP_NAME} v{__version__} ({BRAND}) by {AUTHOR} — Cross-platform ISP filtering diagnostics & fixes")
    sub = p.add_subparsers(dest="cmd")

    pp = sub.add_parser("probe", help="Run DNS, DPI, split_2b, Fastly 5552B, PMTU, and cloud probes")
    pp.add_argument("-i", "--interface", help="Source interface name or IPv4 address")
    pp.add_argument("--quick", action="store_true", help="Skip cloud VPS probes")
    pp.add_argument("--json", action="store_true", help="Output JSON")

    pd = sub.add_parser("doctor", help="Cross-platform read-only network & DNS diagnostics")
    pd.add_argument("-i", "--interface", help="Source interface name or IPv4 address")
    pd.add_argument("--json", action="store_true", help="Output JSON")

    ph = sub.add_parser("hosts-pin", help="Pin healthy Fastly POPs in system hosts file")
    ph.add_argument("action", choices=["status", "apply", "revert"])
    ph.add_argument("--no-apt-ipv4", action="store_true", help="Skip Linux APT IPv4 config")

    pw = sub.add_parser("wg-prepare", help="Optimize any WireGuard .conf (MTU 1280, Keepalive 25, DoH Endpoint)")
    pw.add_argument("input_conf", help="Input WireGuard .conf file")
    pw.add_argument("-o", "--output", help="Output .conf file path (prints to stdout if omitted)")
    pw.add_argument("--mtu", type=int, default=1280)
    pw.add_argument("--keepalive", type=int, default=25)
    pw.add_argument("--keep-dns", action="store_true")
    pw.add_argument("--dns", help="Explicit DNS IP to set under [Interface]")

    pc = sub.add_parser("dns-config", help="Generate IP-only DoH dnscrypt-proxy configuration")
    pc.add_argument("--target", choices=["auto", "crossplatform", "systemd"], default="auto")
    pc.add_argument("-o", "--output", help="Output TOML file path")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "probe":
        return cmd_probe(args)
    if args.cmd in (None, "doctor"):
        if args.cmd is None:
            args = parser.parse_args(["doctor"])
        return cmd_doctor(args)
    if args.cmd == "hosts-pin":
        return cmd_hosts_pin(args)
    if args.cmd == "wg-prepare":
        return cmd_wg_prepare(args)
    if args.cmd == "dns-config":
        return cmd_dns_config(args)
    parser.print_help()
    return 1
