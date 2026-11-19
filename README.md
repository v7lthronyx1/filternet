# FilterNet

Cross-platform ISP filtering diagnostics, encrypted DNS profiles, Fastly mirror pinning, and WireGuard helpers built for **Windows**, **macOS**, and **Linux**.

Developed by **Aiden Azad** — **[V7lthronyx](https://github.com/v7lthronyx1)**

> [نسخه فارسی راهنما (README_FA.md)](README_FA.md)

---

## Why FilterNet Exists

Packet-level audits across filtered cellular and fixed-line networks (initially mapped across three sessions on MCI `AS197207` — see [docs/MCI_FORENSIC_FINDINGS.md](docs/MCI_FORENSIC_FINDINGS.md)) showed that broken VPNs, `apt`/`pip` stalls, and DNS leaks are rarely random:

1. **Plaintext & Port `5353` DNS Hijacking + `HTTPS` RR Stripping:** UDP/TCP `53` and `5353` return sinkholes (`10.10.34.36`), forced SafeSearch (`216.239.38.120`), or RFC1918 redirects (`10.110.10.1`), while `0/30` `HTTPS/SVCB` records survive.
2. **Selective `DoT`, `DoQ`, and Domain-SNI `DoH` Suppression:** `portquiz.net:853` stays open, yet `0/7` international `DoT (853/tcp)`, `0/2` `DoQ (853/udp)`, and `0/5` domain-SNI `DoH` providers connect — while **bare-IP DoH (`1.1.1.1`, `1.0.0.1`, `8.8.8.8`, `8.8.4.4` on `443/tcp`)** works cleanly.
3. **Shallow SNI DPI (`TTL=60`, `NSV2`) & `split_2b` Evasion:** Middleboxes inject `TCP RST` (`p=2.73e-34`) and HTTP `403 NSV2` even against non-existent domains (`probe-test-404.*` on Hetzner and Vultr). Padding (`1800 B`), `TLS 1.2`, and `ECH-GREASE` fail, whereas **`split_2b`** and **`rec_split_2`/`5`** bypass inspection; `QUIC v1 (UDP/443)` suffers `100%` silent drop.
4. **Fastly `151.101.18.132` (`5,552 B` Stall):** Debian and PyPI transfers hitting Fastly POP `151.101.18.132` stall after `5,552 B` (`4 x 1388 B` MSS), breaking updates unless pinned to healthy sibling POPs (`146.75.118.132`, `151.101.130.132`, `151.101.66.132`, `151.101.194.132`, `151.101.0.223`).
5. **Cloud Blackholes & WireGuard Breakage:** `26/57` (`45.6%`) tested cloud endpoints failed on MCI (`Linode`, `DigitalOcean`, `OVH`, `Microsoft 150.171.109.71` core loops) while `Hetzner`, `Vultr`, `Cloudflare`, `GitHub`, and `Ubuntu Archive` stayed reachable. WireGuard profiles need `MTU = 1280`, `PersistentKeepalive = 25`, no conflicting `DNS =` override, and clean endpoint IP resolution.

For full `dumpcap`/`tshark` PCAP captures and regulatory complaint PDFs (`195.cra.ir`), pair this toolkit with **[shitnet](https://github.com/v7lthronyx1/shitnet)**.

---

## Quick Start (Windows / macOS / Linux)

Zero external Python packages required (`Python 3.9+` standard library only).

Run directly from source:
```bash
git clone https://github.com/v7lthronyx1/filternet.git
cd filternet
python3 -m filternet doctor
```

Or install the `filternet` CLI globally:
```bash
pip install .
```

### Core Cross-Platform Commands

- **Read-only system, DNS, Fastly & PMTU snapshot:**
  ```bash
  filternet doctor
  ```
- **Active filtering, DPI `split_2b`, synthetic SNI & cloud VPS probe:**
  ```bash
  filternet probe
  filternet probe --quick --json
  ```
- **Check or pin healthy Fastly POPs in the OS `hosts` file (Windows Admin / `sudo`):**
  ```bash
  filternet hosts-pin status
  filternet hosts-pin apply
  filternet hosts-pin revert
  ```
- **Prepare any WireGuard `.conf` (`MTU = 1280`, `Keepalive = 25`, bare-IP DoH endpoint, clean DNS):**
  ```bash
  filternet wg-prepare raw-profile.conf -o clean-profile.conf
  ```
- **Generate an IP-only DoH `dnscrypt-proxy` config for your OS:**
  ```bash
  filternet dns-config --target crossplatform -o dnscrypt-proxy.toml
  ```

See [docs/CROSS_PLATFORM_GUIDE.md](docs/CROSS_PLATFORM_GUIDE.md) for OS-specific instructions on Windows, macOS, and Linux.

---

## Linux System Scripts

- [scripts/diagnose-vpn.sh](scripts/diagnose-vpn.sh): Read-only check covering NetworkManager, `172.20.0.0/16` orphan bridges, `ip rule` / `nft`, Surfshark `cache.json`, DNS/`5353`/`HTTPS RR`, `PortQuiz`, Fastly `5552 B`, and `PMTU`.
- [scripts/ss-wg](scripts/ss-wg): WireGuard cleaner and endpoint rotator (`fix-system`, `up [phx|lax|<profile>|/path/to/conf] [--force]`, `down`, `clean`, `status`).
- [scripts/fix-fastly-apt.sh](scripts/fix-fastly-apt.sh): Pins healthy Fastly mirrors in `/etc/hosts` and installs `Acquire::ForceIPv4 "true";` for APT (`status`, `apply`, `revert`).
- [scripts/probe-filtering.py](scripts/probe-filtering.py): Direct runner for `filternet probe`.

---

## Repository Layout

- `filternet/`: Cross-platform Python 3.9+ CLI package (`cli.py`, `net_os.py`, `dns_raw.py`, `dpi.py`, `fastly.py`, `hosts_mgr.py`, `wg_conf.py`)
- `configs/dnscrypt-proxy/`: `dnscrypt-proxy-crossplatform.toml` (`127.0.0.1:53`), `dnscrypt-proxy.toml` (`systemd` socket), and `resolved.conf`
- `configs/wireguard/`: Sanitized `surfshark-wg.conf.example` template
- `configs/NetworkManager/`: `90-ss-wg-unmanaged.conf`
- `configs/hosts/` & `configs/apt/`: `fastly-healthy-mirrors.hosts` and `99-filternet-ipv4.conf`
- `docs/`: [CROSS_PLATFORM_GUIDE.md](docs/CROSS_PLATFORM_GUIDE.md), [MCI_FORENSIC_FINDINGS.md](docs/MCI_FORENSIC_FINDINGS.md), [TIMELINE_AND_FIXES.md](docs/TIMELINE_AND_FIXES.md), [DIAGNOSTICS_GUIDE.md](docs/DIAGNOSTICS_GUIDE.md)
- `scripts/`: Linux Bash wrappers and CLI runner
- `tests/`: Offline `unittest` suite (`python -m unittest discover -s tests -v`)

---

## License

MIT License — Copyright (c) 2026 **Aiden Azad (V7lthronyx)**
