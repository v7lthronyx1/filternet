# Security & OPSEC Policy

## Never Commit Sensitive Network Data

Before pushing a branch or opening an issue with command output:
- Redact subscriber public IP addresses, local LAN/tether IPs (`192.168.x.x`, `10.x.x.x`), usernames, and hostnames.
- Never commit `*.conf`, `*.ovpn`, `*.key`, `*.pem`, `*.pcap`, `*.pcapng`, or VPN client `cache.json` files.
- Keep `configs/wireguard/surfshark-wg.conf.example` strictly sanitized with placeholder keys.

## Reporting Vulnerabilities

If you spot a bug in privilege/hosts handling (`filternet/hosts_mgr.py`, `scripts/ss-wg`, `scripts/fix-fastly-apt.sh`) or unintended secret leakage, report it privately via GitHub security advisories at [github.com/v7lthronyx1/filternet](https://github.com/v7lthronyx1/filternet) or contact **Aiden Azad (V7lthronyx)**.
