# Root Causes & Applied Fixes

Technical record of filtering mechanisms, local networking conflicts, and verified fixes across Linux, macOS, and Windows.

---

## 1. Conflicting VPN Client Packages (Linux)
- Running sandboxed Snap or Flatpak VPN builds alongside native `.deb` daemons creates competing policy routes and socket hooks.
- **Fix:** Purge sandboxed installs (`flatpak uninstall`, `snap remove --purge`) and stick to a single native package (`apt` repository / official `.deb`).

---

## 2. Plain DNS Poisoning (`10.10.34.x`), Port `5353`, & Blocked DoT/DoQ
### Symptoms
- Plain UDP/TCP port `53` and non-standard port `5353` return poisoned sinkhole IPs (`10.10.34.35` / `10.10.34.36`), SafeSearch hijacks (`216.239.38.120`), or RFC1918 redirects (`10.110.10.1`).
- `HTTPS` (Type 65) resource records are stripped (`0/30`), and `DoT (853/tcp)`, `DoQ (853/udp)`, and domain-SNI `DoH` fail even when `portquiz.net:853` is open.
- VPN client caches (e.g., Surfshark `cache.json` `dns_lookup|*` entries) persist stale `10.10.34.36` records until purged.

### Fixes
1. **Clean stale client DNS caches:** Remove cached `10.10.34.*` records when switching from unfiltered/filtered DNS.
2. **Use bare-IP DoH (`dnscrypt-proxy`):**
   - Windows / macOS / non-systemd Linux: [configs/dnscrypt-proxy/dnscrypt-proxy-crossplatform.toml](../configs/dnscrypt-proxy/dnscrypt-proxy-crossplatform.toml) (`127.0.0.1:53`, static IP-only DoH stamps for `1.1.1.1`, `1.0.0.1`, `8.8.8.8`, `8.8.4.4`).
   - Linux `systemd-socket`: [configs/dnscrypt-proxy/dnscrypt-proxy.toml](../configs/dnscrypt-proxy/dnscrypt-proxy.toml) (`127.0.2.1:53`) + [configs/dnscrypt-proxy/resolved.conf](../configs/dnscrypt-proxy/resolved.conf) (`DNS=127.0.2.1`, `FallbackDNS=`, `DNSOverTLS=no`).
   - Generate either config anytime with `filternet dns-config`.
3. **Keep `/etc/resolv.conf` mutable on Linux:** Unlock (`chattr -i /etc/resolv.conf`) when switching between `dnscrypt-proxy` and desktop VPN clients that prepend their internal tunnel DNS.

---

## 3. Orphan `172.20.0.0/16` Bridges (`EHOSTUNREACH`)
### Symptoms
- Container/Virtual bridges (`br-*`) holding `172.20.0.0/16` hijack VPN internal SDN subnets (`172.20.21.246:7474`), leaving the tunnel connected in UI while dropping all traffic (`EHOSTUNREACH`).

### Fix
- Inspect `ip -4 route show | grep '172\.20\.'` and delete unused `br-*` bridges from NetworkManager (`nmcli connection delete <name>`) and the kernel (`ip link delete <name>`).

---

## 4. OpenVPN DPI Blackholes & Manual WireGuard Optimization
### Symptoms
- Standard OpenVPN handshakes succeed and pass ~20 KB before DPI blackholes return traffic.
- Desktop VPN GUI WireGuard logins fail when API domains (such as `ext2.surfshark.com`) hit SNI RST injection before fetching keys.

### Fix (`filternet wg-prepare` & `scripts/ss-wg`)
- Export manual WireGuard `.conf` profiles, then run `filternet wg-prepare` (cross-platform) or `scripts/ss-wg` (Linux):
  - Strips conflicting `DNS = ...` entries
  - Sets `MTU = 1280` (compatible with cellular tethering under `PMTU = 1500 B`)
  - Sets `PersistentKeepalive = 25`
  - Resolves domain endpoints via bare-IP DoH (`1.1.1.1/dns-query`)
  - On Linux, `scripts/ss-wg fix-system` clears stale `wg-quick` `ip rule`/`nft` leftovers, disables conflicting leftover VPN services or broken `/etc/NetworkManager/dispatcher.d/*` scripts, and installs `90-ss-wg-unmanaged.conf` (`unmanaged-devices=interface-name:ss-*`).

---

## 5. Windscribe Configuration Findings on Tethered Mobile Links
- **`customSniDomain` format:** Save a bare hostname (`github.com`) or leave blank; full URLs (`https://github.com/`) fail validation.
- **`Protocol Tweaks`:** Presets can trigger `packet was truncated/expanded` errors on `WStunnel`/`Stealth` and stalls on `WireGuard`.
- **`MAC Spoofing (Auto-rotate)`:** Can stall link switching (`eth0` <-> `wlan0`) for 30+ seconds.
- **Region selection:** When US gateways blackhole after tunnel handshake on cellular tethering, test European gateways (`Frankfurt`, `Amsterdam`) and keep only one VPN active at a time.

---

## 6. Fastly `151.101.18.132` (`5,552 B` Stall) Fix (`apt` / `PyPI` / GitHub)
### Symptoms
- HTTP/HTTPS transfers from `deb.debian.org` landing on Fastly POP `151.101.18.132` stall after `5,552` payload bytes (`4 x 1388 B` MSS, `17` retransmissions in PCAP), hanging `apt update` and `pip`.

### Fix (`filternet hosts-pin` & `scripts/fix-fastly-apt.sh`)
- `filternet hosts-pin status` tests `151.101.18.132` vs healthy sibling Fastly POPs (`146.75.118.132`, `151.101.130.132`, `151.101.66.132`) with a `20 KB` range download.
- `filternet hosts-pin apply` pins verified healthy IPs for `deb.debian.org`, `security.debian.org` (`151.101.194.132`), and `pypi.org` (`151.101.0.223`) in the OS `hosts` file (`Windows`, `macOS`, `Linux`), flushes DNS cache, and writes [configs/apt/99-filternet-ipv4.conf](../configs/apt/99-filternet-ipv4.conf) on Linux.
- `filternet hosts-pin revert` removes managed pins cleanly.

---

## 7. VPS Selection & DPI Parser Findings
- **VPS / Proxy Routing:** Multi-session MCI probes (`57` endpoints; details in [MCI_FORENSIC_FINDINGS.md](MCI_FORENSIC_FINDINGS.md)) showed **Linode** (`5/6` blackholed), **DigitalOcean** (`0/7`), and **OVH** (`4/6` blackholed/looped/RST) suffer heavy disruption, while **Hetzner (`3/3`)**, **Vultr (`2/2`)**, **Cloudflare**, **GitHub**, and **Ubuntu Archive** stay reachable.
- **DPI Framing:** `tls12`, `pad1800`, and `ech_grease` (`0xfe0d`) all fail against MCI's DPI injector (`120/134` resets at `TTL=60`, `p=2.73e-34`); only **`split_2b`** (2-byte TCP splits) and **`rec_split_2`/`5`** (TLS record splitting) bypassed inspection, and `QUIC v1 (UDP/443)` experienced `100%` silent drop.
