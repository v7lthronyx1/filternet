import concurrent.futures
import json
import os
import socket
import struct
import time
import urllib.parse
from .net_os import detect_local_dns_servers, http_fetch_pinned


def encode_dns_name(domain):
    parts = [p.encode("ascii") for p in domain.strip(".").split(".") if p]
    return b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"


def skip_dns_name(wire, offset):
    length = len(wire)
    while offset < length:
        b = wire[offset]
        if b == 0:
            return offset + 1
        if (b & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + b
    return length


def build_dns_query(domain, rtype_code=1, txid=None):
    if txid is None:
        txid = struct.unpack("!H", os.urandom(2))[0]
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_dns_name(domain) + struct.pack("!HH", rtype_code, 1)
    return header + question


def parse_dns_reply(wire):
    res = {"ok": False, "rcode": None, "ips": [], "https_rr": 0, "ttl": None}
    if len(wire) < 12:
        return res
    _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", wire[:12])
    res["rcode"] = flags & 0x0F
    res["ok"] = True
    off = 12
    for _ in range(qdcount):
        off = skip_dns_name(wire, off) + 4
    for _ in range(ancount):
        if off >= len(wire):
            break
        off = skip_dns_name(wire, off)
        if off + 10 > len(wire):
            break
        atype, _, ttl, rdlen = struct.unpack("!HHIH", wire[off : off + 10])
        off += 10
        rdata = wire[off : off + rdlen]
        off += rdlen
        if res["ttl"] is None:
            res["ttl"] = ttl
        if atype == 1 and len(rdata) == 4:
            res["ips"].append(socket.inet_ntop(socket.AF_INET, rdata))
        elif atype == 28 and len(rdata) == 16:
            res["ips"].append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif atype == 65:
            res["https_rr"] += 1
    return res


def query_dns_raw(server_ip, domain, rtype_code=1, port=53, proto="udp", source_ip=None, timeout=2.0):
    res = {"ok": False, "rcode": None, "ips": [], "https_rr": 0, "ttl": None, "rtt_ms": None, "error": None}
    packet = build_dns_query(domain, rtype_code=rtype_code)
    s = None
    try:
        t0 = time.monotonic()
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            if source_ip:
                s.bind((source_ip, 0))
            s.sendto(packet, (server_ip, port))
            wire, _ = s.recvfrom(4096)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if source_ip:
                s.bind((source_ip, 0))
            s.connect((server_ip, port))
            s.sendall(struct.pack("!H", len(packet)) + packet)
            hdr = b""
            while len(hdr) < 2:
                chunk = s.recv(2 - len(hdr))
                if not chunk:
                    raise EOFError("short tcp dns header")
                hdr += chunk
            need = struct.unpack("!H", hdr)[0]
            wire = b""
            while len(wire) < need:
                chunk = s.recv(need - len(wire))
                if not chunk:
                    raise EOFError("short tcp dns body")
                wire += chunk
        res["rtt_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
        parsed = parse_dns_reply(wire)
        if not parsed["ok"]:
            res["error"] = "short_dns_reply"
            return res
        res.update(parsed)
    except PermissionError as e:
        res["error"] = f"HOST_SOCKET_EPERM: {e}"
    except Exception as e:
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def resolve_doh_a(domain, source_ip=None, timeout=4.0):
    qname = urllib.parse.quote(domain.strip())
    for srv_ip in ("1.1.1.1", "1.0.0.1"):
        r = http_fetch_pinned(
            srv_ip,
            srv_ip,
            f"/dns-query?name={qname}&type=A",
            port=443,
            https=True,
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
            source_ip=source_ip,
        )
        if r["ok"] and r["body"]:
            try:
                data = json.loads(r["body"].decode("utf-8", "replace"))
                ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
                if ips:
                    return ips
            except Exception:
                pass
    return []


def classify_dns_verdict(res):
    if not res["ok"]:
        return res["error"] or "ERROR"
    ips = set(res["ips"])
    if any(ip.startswith("10.10.34.") for ip in ips):
        return f"SINKHOLE ({','.join(res['ips'])})"
    if "216.239.38.120" in ips:
        return "FORCED_SAFESEARCH (216.239.38.120)"
    if any(ip.startswith(("10.", "192.168.", "172.16.")) for ip in ips):
        return f"PRIVATE_HIJACK ({','.join(res['ips'])})"
    return f"OK ({','.join(res['ips'])})"


def pick_local_stub():
    configured = detect_local_dns_servers()
    for cand in ("127.0.2.1", "127.0.0.1"):
        if cand in configured:
            return cand
    return "127.0.2.1"


def run_dns_checks(source_ip=None):
    stub = pick_local_stub()
    checks = [
        ("local_stub_x", stub, 53, "udp", "x.com", 1),
        ("local_stub_https_rr", stub, 53, "udp", "cloudflare.com", 65),
        ("udp53_8844_x", "8.8.4.4", 53, "udp", "x.com", 1),
        ("udp53_8844_google", "8.8.4.4", 53, "udp", "google.com", 1),
        ("udp53_8844_mci", "8.8.4.4", 53, "udp", "mci.ir", 1),
        ("udp53_8844_https_rr", "8.8.4.4", 53, "udp", "cloudflare.com", 65),
        ("udp5353_opendns_x", "208.67.222.222", 5353, "udp", "x.com", 1),
        ("tcp5353_opendns_x", "208.67.222.222", 5353, "tcp", "x.com", 1),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {label: ex.submit(query_dns_raw, srv, dom, rcode, port, proto, source_ip) for label, srv, port, proto, dom, rcode in checks}
        return {label: fut.result() for label, fut in futs.items()}
