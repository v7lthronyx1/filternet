import ipaddress
from .dns_raw import resolve_doh_a


def parse_wg_conf(text):
    sections = []
    cur_name = None
    cur_items = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            if cur_name is not None:
                sections.append((cur_name, cur_items))
            cur_name = line[1:-1].strip()
            cur_items = []
        elif "=" in line and cur_name is not None:
            k, v = line.split("=", 1)
            cur_items.append((k.strip(), v.strip()))
    if cur_name is not None:
        sections.append((cur_name, cur_items))
    return sections


def format_wg_conf(sections):
    blocks = []
    for name, items in sections:
        lines = [f"[{name}]"]
        for k, v in items:
            lines.append(f"{k} = {v}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) + "\n"


def _is_ipv4(val):
    try:
        ipaddress.IPv4Address(val)
        return True
    except ValueError:
        return False


def prepare_wg_config(text, mtu=1280, keepalive=25, drop_dns=True, custom_dns=None, resolved_endpoint_ip=None, resolve_fn=None):
    sections = parse_wg_conf(text)
    if not sections:
        raise ValueError("No valid WireGuard sections found")

    resolver = resolve_fn or resolve_doh_a
    out_sections = []
    resolved_ips = []
    endpoint_host = None

    for sec_name, items in sections:
        low_sec = sec_name.lower()
        new_items = []
        if low_sec == "interface":
            has_mtu = False
            has_dns = False
            for k, v in items:
                lk = k.lower()
                if lk == "dns":
                    if custom_dns:
                        new_items.append(("DNS", custom_dns))
                        has_dns = True
                    elif not drop_dns:
                        new_items.append((k, v))
                        has_dns = True
                elif lk == "mtu":
                    new_items.append(("MTU", str(mtu)))
                    has_mtu = True
                else:
                    new_items.append((k, v))
            if not has_mtu:
                new_items.append(("MTU", str(mtu)))
            if custom_dns and not has_dns:
                new_items.append(("DNS", custom_dns))
        elif low_sec == "peer":
            has_ka = False
            for k, v in items:
                lk = k.lower()
                if lk == "persistentkeepalive":
                    new_items.append(("PersistentKeepalive", str(keepalive)))
                    has_ka = True
                elif lk == "endpoint":
                    if ":" in v and not v.startswith("["):
                        host, port = v.rsplit(":", 1)
                        endpoint_host = host
                        if _is_ipv4(host):
                            resolved_ips = [host]
                            new_items.append(("Endpoint", v))
                        else:
                            if resolved_endpoint_ip:
                                resolved_ips = [resolved_endpoint_ip]
                            else:
                                resolved_ips = resolver(host) or []
                            if resolved_ips:
                                new_items.append(("Endpoint", f"{resolved_ips[0]}:{port}"))
                            else:
                                new_items.append(("Endpoint", v))
                    else:
                        new_items.append((k, v))
                else:
                    new_items.append((k, v))
            if not has_ka:
                new_items.append(("PersistentKeepalive", str(keepalive)))
        else:
            new_items = list(items)
        out_sections.append((sec_name, new_items))

    return {
        "text": format_wg_conf(out_sections),
        "endpoint_host": endpoint_host,
        "resolved_ips": resolved_ips,
    }
