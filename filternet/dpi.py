import concurrent.futures
import json
import os
import socket
import ssl
import struct
import time
from .net_os import bind_socket, http_fetch_pinned, pmtu_check


def build_client_hello(sni, tls12=False, pad_to=0, grease_ech=False):
    rand_bytes = os.urandom(32)
    sess_id = os.urandom(32)
    ciphers = b"\x13\x01\x13\x02\x13\x03\xc0\x2f\xc0\x2b\xc0\x30\xc0\x2c\xcc\xa9\xcc\xa8"
    sni_bytes = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_ext = struct.pack("!HH", 0x0000, len(sni_entry) + 2) + struct.pack("!H", len(sni_entry)) + sni_entry
    alpn_list = b"\x02h2\x08http/1.1"
    alpn_ext = struct.pack("!HH", 0x0010, len(alpn_list) + 2) + struct.pack("!H", len(alpn_list)) + alpn_list
    sig_algs = b"\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01"
    sig_ext = struct.pack("!HH", 0x000D, len(sig_algs) + 2) + struct.pack("!H", len(sig_algs)) + sig_algs
    groups = b"\x00\x1D\x00\x17\x00\x18"
    groups_ext = struct.pack("!HH", 0x000A, len(groups) + 2) + struct.pack("!H", len(groups)) + groups
    exts = sni_ext + alpn_ext + sig_ext + groups_ext
    if not tls12:
        ver_list = b"\x03\x04\x03\x03"
        exts += struct.pack("!HH", 0x002B, len(ver_list) + 1) + bytes([len(ver_list)]) + ver_list
        key_pub = os.urandom(32)
        ks_entry = struct.pack("!HH", 0x001D, len(key_pub)) + key_pub
        exts += struct.pack("!HH", 0x0033, len(ks_entry) + 2) + struct.pack("!H", len(ks_entry)) + ks_entry
    if grease_ech:
        ech_payload = os.urandom(168)
        exts += struct.pack("!HH", 0xFE0D, len(ech_payload)) + ech_payload
    if pad_to > 0:
        cur_len = 2 + 32 + 1 + len(sess_id) + 2 + len(ciphers) + 2 + 2 + len(exts) + 4
        if cur_len < pad_to:
            pad_len = pad_to - cur_len
            exts += struct.pack("!HH", 0x0015, pad_len) + (b"\x00" * pad_len)
    body = (
        b"\x03\x03"
        + rand_bytes
        + bytes([len(sess_id)])
        + sess_id
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def classify_tls_bytes(data):
    if not data:
        return "EOF_CLOSE"
    rtype = data[0]
    if rtype == 0x16 and len(data) > 5 and data[5] == 0x02:
        return "TLS_SERVER_HELLO"
    if rtype == 0x15 and len(data) >= 7:
        return f"TLS_ALERT_{data[5]}_{data[6]}"
    if data.startswith(b"HTTP/"):
        first_line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
        return f"RAW_HTTP_{first_line}"
    return f"DATA_{rtype:#x}"


def raw_tls_probe(ip, sni, source_ip=None, mode="normal", port=443, timeout=3.2, bind_iface=None):
    res = {"ok": False, "outcome": None, "tcp_ms": None, "tls_ms": None, "error": None}
    s = None
    t0 = time.monotonic()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        bind_socket(s, source_ip=source_ip, bind_iface=bind_iface)
        s.connect((ip, port))
        res["tcp_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        if mode == "tls12":
            hs = build_client_hello(sni, tls12=True)
        elif mode == "pad1800":
            hs = build_client_hello(sni, pad_to=1800)
        elif mode == "ech_grease":
            hs = build_client_hello(sni, grease_ech=True)
        else:
            hs = build_client_hello(sni)
        t1 = time.monotonic()
        if mode in ("normal", "tls12", "pad1800", "ech_grease"):
            s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs)
        elif mode == "split_5b":
            rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
            s.sendall(rec[:5])
            time.sleep(0.015)
            s.sendall(rec[5:])
        elif mode == "split_midsni":
            rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
            idx = rec.find(sni.encode("ascii"))
            cut = idx + max(1, len(sni) // 2) if idx > 0 else len(rec) // 2
            s.sendall(rec[:cut])
            time.sleep(0.015)
            s.sendall(rec[cut:])
        elif mode == "split_2b":
            rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for off in range(0, min(80, len(rec)), 2):
                s.sendall(rec[off : off + 2])
                time.sleep(0.002)
            if len(rec) > 80:
                s.sendall(rec[80:])
        elif mode == "rec_split_2":
            idx = hs.find(sni.encode("ascii"))
            cut = idx + max(1, len(sni) // 2) if idx > 0 else len(hs) // 2
            p1, p2 = hs[:cut], hs[cut:]
            s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(p1)) + p1)
            s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(p2)) + p2)
        elif mode == "rec_split_5":
            n = max(1, len(hs) // 5)
            for i in range(0, len(hs), n):
                c = hs[i : i + n]
                s.sendall(b"\x16\x03\x01" + struct.pack("!H", len(c)) + c)
        data = s.recv(4096)
        res["tls_ms"] = round((time.monotonic() - t1) * 1000.0, 2)
        res["outcome"] = classify_tls_bytes(data)
        res["ok"] = res["outcome"] == "TLS_SERVER_HELLO"
    except ConnectionResetError as e:
        res["tls_ms"] = round((time.monotonic() - t0) * 1000.0, 2) if res["tcp_ms"] else None
        res["outcome"] = "TCP_RST_INJECTED"
        res["error"] = str(e)
    except TimeoutError as e:
        res["outcome"] = "TCP_TIMEOUT" if res["tcp_ms"] is None else "TLS_TIMEOUT"
        res["error"] = str(e)
    except OSError as e:
        res["outcome"] = f"OS_ERR_{e.errno}"
        res["error"] = str(e)
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def http_host_probe(ip, host, source_ip=None, timeout=2.5, bind_iface=None):
    res = {"ok": False, "status": None, "block_sig": None, "error": None}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        bind_socket(s, source_ip=source_ip, bind_iface=bind_iface)
        s.connect((ip, 80))
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode("ascii")
        s.sendall(req)
        raw = s.recv(4096).decode("latin1", "replace")
        first = raw.split("\r\n", 1)[0]
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            res["status"] = int(parts[1])
            res["ok"] = True
        low = raw.lower()
        if "nsv2" in low or "mainpolicy" in low or "10.10.34." in low or "peyvandha" in low:
            res["block_sig"] = "ISP_HTTP_BLOCKPAGE_NSV2"
        elif res["status"] == 403:
            res["block_sig"] = "HTTP_403"
    except ConnectionResetError as e:
        res["block_sig"] = "TCP_RST_ON_HTTP"
        res["error"] = str(e)
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def https_status_probe(ip, host, source_ip=None, timeout=3.5, bind_iface=None):
    res = {"ok": False, "status": None, "error": None}
    s = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        bind_socket(s, source_ip=source_ip, bind_iface=bind_iface)
        s.connect((ip, 443))
        ws = ctx.wrap_socket(s, server_hostname=host)
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: FilterNet/1.0\r\nConnection: close\r\n\r\n".encode("ascii")
        ws.sendall(req)
        raw = ws.recv(2048).decode("latin1", "replace")
        ws.close()
        first = raw.split("\r\n", 1)[0]
        parts = first.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            res["status"] = int(parts[1])
            res["ok"] = True
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def probe_tcp_port(ip, port, source_ip=None, timeout=2.5, bind_iface=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    bind_socket(s, source_ip=source_ip, bind_iface=bind_iface)
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
        return {"ok": True, "ms": round((time.monotonic() - t0) * 1000.0, 2), "err": None}
    except Exception as e:
        return {"ok": False, "ms": round((time.monotonic() - t0) * 1000.0, 2), "err": f"{type(e).__name__}: {e}"}
    finally:
        s.close()


def dot_handshake_probe(ip, sni, source_ip=None, timeout=3.0, bind_iface=None):
    res = {"tcp_ok": False, "tls_ok": False, "ms": None, "err": None}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    bind_socket(s, source_ip=source_ip, bind_iface=bind_iface)
    t0 = time.monotonic()
    try:
        s.connect((ip, 853))
        res["tcp_ok"] = True
        ws = ctx.wrap_socket(s, server_hostname=sni)
        res["tls_ok"] = True
        res["ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        ws.close()
    except Exception as e:
        res["ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        res["err"] = f"{type(e).__name__}: {e}"
        try:
            s.close()
        except Exception:
            pass
    return res


def doh_probe(ip, host_hdr, source_ip=None, timeout=4.0, bind_iface=None):
    r = http_fetch_pinned(
        ip,
        host_hdr,
        "/dns-query?name=example.com&type=A",
        port=443,
        https=True,
        headers={"Accept": "application/dns-json"},
        timeout=timeout,
        source_ip=source_ip,
        bind_iface=bind_iface,
    )
    return {"ok": r["http_code"] == 200, "http_code": str(r["http_code"]) if r["http_code"] else None, "err": r["err"]}


def ntp_probe(ip, source_ip=None, bind_iface=None):
    pkt = b"\x1b" + (47 * b"\x00")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.2)
    bind_socket(s, source_ip=source_ip, bind_iface=bind_iface)
    t0 = time.monotonic()
    try:
        s.sendto(pkt, (ip, 123))
        data, _ = s.recvfrom(256)
        return {"ok": len(data) >= 48, "ms": round((time.monotonic() - t0) * 1000.0, 2)}
    except Exception as e:
        return {"ok": False, "err": f"{type(e).__name__}: {e}"}
    finally:
        s.close()


def resolve_portquiz_ip(source_ip=None, bind_iface=None):
    r = http_fetch_pinned(
        "1.1.1.1",
        "1.1.1.1",
        "/dns-query?name=portquiz.net&type=A",
        port=443,
        https=True,
        headers={"Accept": "application/dns-json"},
        timeout=2.0,
        source_ip=source_ip,
        bind_iface=bind_iface,
    )
    if r.get("http_code") == 200 and r.get("body"):
        try:
            data = json.loads(r["body"])
            for ans in data.get("Answer", []):
                ip = str(ans.get("data", "")).strip()
                if ans.get("type") == 1 and ip:
                    socket.inet_aton(ip)
                    return ip
        except Exception:
            pass
    return "13.216.200.40"


def run_protocol_checks(source_ip=None, bind_iface=None):
    pq_ip = resolve_portquiz_ip(source_ip=source_ip, bind_iface=bind_iface)
    tasks = {
        "portquiz_443": (probe_tcp_port, (pq_ip, 443, source_ip, 2.5, bind_iface)),
        "portquiz_853": (probe_tcp_port, (pq_ip, 853, source_ip, 2.5, bind_iface)),
        "portquiz_51820": (probe_tcp_port, (pq_ip, 51820, source_ip, 2.5, bind_iface)),
        "dot_1111": (dot_handshake_probe, ("1.1.1.1", "cloudflare-dns.com", source_ip, 3.0, bind_iface)),
        "dot_adguard": (dot_handshake_probe, ("94.140.14.14", "dns.adguard-dns.com", source_ip, 3.0, bind_iface)),
        "doh_ip_1111": (doh_probe, ("1.1.1.1", "1.1.1.1", source_ip, 4.0, bind_iface)),
        "doh_domain_cf": (doh_probe, ("104.16.248.249", "cloudflare-dns.com", source_ip, 4.0, bind_iface)),
        "ntp_google": (ntp_probe, ("216.239.35.4", source_ip, bind_iface)),
        "ntp_cloudflare": (ntp_probe, ("162.159.200.1", source_ip, bind_iface)),
        "pmtu_1500_ok": (pmtu_check, ("1.1.1.1", 1472, source_ip, bind_iface)),
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futs = {k: ex.submit(fn, *args) for k, (fn, args) in tasks.items()}
        return {k: fut.result() for k, fut in futs.items()}


def run_dpi_checks(source_ip=None, bind_iface=None):
    return {
        "synthetic_hetzner_404": raw_tls_probe("78.46.170.2", "probe-test-404.pages.dev", source_ip=source_ip, mode="normal", bind_iface=bind_iface),
        "synthetic_vultr_404": raw_tls_probe("108.61.210.117", "probe-test-404.pages.dev", source_ip=source_ip, mode="normal", bind_iface=bind_iface),
        "synthetic_hetzner_ctrl": raw_tls_probe("78.46.170.2", "fsn1-speed.hetzner.com", source_ip=source_ip, mode="normal", bind_iface=bind_iface),
        "http_nsv2_404": http_host_probe("78.46.170.2", "probe-test-404.pages.dev", source_ip=source_ip, bind_iface=bind_iface),
        "x_normal": raw_tls_probe("104.16.132.229", "x.com", source_ip=source_ip, mode="normal", bind_iface=bind_iface),
        "x_ech_grease": raw_tls_probe("104.16.132.229", "x.com", source_ip=source_ip, mode="ech_grease", bind_iface=bind_iface),
        "x_split_2b": raw_tls_probe("104.16.132.229", "x.com", source_ip=source_ip, mode="split_2b", bind_iface=bind_iface),
        "x_rec_split_2": raw_tls_probe("104.16.132.229", "x.com", source_ip=source_ip, mode="rec_split_2", bind_iface=bind_iface),
        "do_spaces_normal": raw_tls_probe("5.101.109.44", "fra1.digitaloceanspaces.com", source_ip=source_ip, mode="normal", bind_iface=bind_iface),
        "do_spaces_split_2b": raw_tls_probe("5.101.109.44", "fra1.digitaloceanspaces.com", source_ip=source_ip, mode="split_2b", bind_iface=bind_iface),
        "cloudflare_tls": raw_tls_probe("104.16.132.229", "cloudflare.com", source_ip=source_ip, mode="normal", bind_iface=bind_iface),
        "cloudflare_https": https_status_probe("104.16.132.229", "cloudflare.com", source_ip=source_ip, bind_iface=bind_iface),
    }


def run_cloud_checks(source_ip=None, bind_iface=None):
    cloud_targets = [
        ("Hetzner-FSN1", "78.46.170.2", "fsn1-speed.hetzner.com"),
        ("Vultr-FRA", "108.61.210.117", "fra-de-ping.vultr.com"),
        ("Linode-FRA", "139.162.130.8", "speedtest.frankfurt.linode.com"),
        ("DO-FRA-Pool", "167.99.240.1", "digitalocean.com"),
        ("OVH-Proof", "141.95.207.211", "proof.ovh.net"),
        ("Microsoft-150.171.109.71", "150.171.109.71", "microsoft.com"),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futs = {label: ex.submit(raw_tls_probe, ip, sni, source_ip, "normal", 443, 3.0, bind_iface) for label, ip, sni in cloud_targets}
        return {label: fut.result() for label, fut in futs.items()}
