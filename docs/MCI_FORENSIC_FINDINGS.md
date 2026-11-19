# MCI (AS197207) Multi-Session Forensic Findings

Packet-level measurements recorded across three sessions (`V1 -> V2 -> V3`) on Hamrah-e-Avval / MCI (`AS197207`) over Wi-Fi hotspot (`wlan0`) and USB/Ethernet tethering (`eth0`), against isolated clean VPN baselines.

For automated 6-stage `dumpcap`/`tshark` capture and regulatory filing bundles (`195.cra.ir`), see the companion forensics suite **[shitnet](https://github.com/v7lthronyx1/shitnet)**.

---

## 1. Three-Session Progression (`V1 -> V2 -> V3`)

| Metric | Audit V1 (`wlan0`) | Audit V2 (`wlan0`) | Audit V3 (`eth0`) |
| :--- | :--- | :--- | :--- |
| **Audited Prefix / Exit** | `5.213.x.x` (`AS197207`) | `95.64.x.x` (`AS197207`) | `178.131.x.x` (`178.131.192.0/20`) |
| **Forged DPI `TCP RST` Events** | `76` (`64` at `TTL=60`; median `59.76 ms`) | `126` (`51` at `TTL=60`; median `44.86 ms`, `p=6.65e-34`) | **`134`** (`120` at `TTL=60 = 89.6%`; median `93.86 ms`, **`p=2.73e-34`**) |
| **Cloud / CDN Endpoints Disrupted** | `13 / 32` (`40.6%`) | `25 / 57` (`43.9%`) | **`26 / 57` (`45.6%`)** vs `57/57` TCP OK on VPN |
| **Dual-Server Synthetic SNI Trap** | — | `10 / 18` reset (Hetzner) | **`12 / 20`** reset on **both** Hetzner & Vultr + `12/20` `403 NSV2` |
| **Core MPLS Routing Loops (`10.21.x.x`)** | `150.171.109.71` (Microsoft) | `150.171.109.71` (Hop 30) | Expanded to `141.95.207.211` (OVH, up to `4,219 ms`) + `150.171.109.71` |
| **`PortQuiz:51820` (TCP Control)** | `False` | `False` (`ConnectionRefused`) | `True` (`158.66 ms`) |
| **`Google-DL-5MB` Throughput** | `13.95 Mbps` | Degrading | **`0.24 Mbps`** (`660,793 B`, `rc=28`) |
| **Fastly `151.101.18.132` (`deb.debian.org`)** | Stalled above `5,552 B` | Stalled | Still stalled above `5,552 B` (`17` server retransmissions in PCAP) |

---

## 2. Layer 1: DNS Hijacking (`53` & `5353`), `HTTPS` RR Stripping & Encrypted DNS

Audit V3 (`122` domains and `18` external resolver configurations) established why bare-IP DoH is the only reliable non-VPN resolver setup:

1. **Plaintext & Non-Standard Port Hijacking (`102` forged PCAP replies, `TTL = 60 / 191 / 192`, median `39.52 ms` vs clean `126.13 ms`):**
   - Filtered domains sinkhole to `10.10.34.36` (with `youtube.com` `AAAA` poisoned to `2001:4188:2:600:10:10:34:36`).
   - Search domains (`google.com`, `bing.com`) are forced to SafeSearch (`216.239.38.120`).
   - `mci.ir` resolves to private RFC1918 IP `10.110.10.1`.
   - External resolvers (`114.114.114.114`, `8.8.4.4`, `1.0.0.1`, `9.9.9.9`, `94.140.14.14`, `45.90.28.0`, `208.67.222.222`) are hijacked across **both port `53` and port `5353` (UDP & TCP)**.
2. **Record & Security Stripping:**
   - **`HTTPS` (Type 65) / `SVCB` records stripped `100%` (`0/30` on MCI vs `30/30` on VPN)**, blocking ECH bootstrap and HTTP/3 hints.
   - **`DNSSEC` degraded** from `18` (`VPN`) to `13` (`MCI`).
3. **Encrypted DNS Suppression Despite Open Port `853`:**
   - `portquiz.net:853` (and all `33/33` tested `PortQuiz` TCP ports in V3) connected cleanly (`130.57 ms`).
   - **`0/7` international DoT (`TCP/853`)** resolvers worked (`1.1.1.1`, `8.8.8.8`, `9.9.9.9`, `208.67.222.222` timed out; `AdGuard`, `NextDNS`, `CleanBrowsing` got forged `TCP RST` `TTL=60`).
   - **`0/2` DoQ (`UDP/853`)** resolvers (`AdGuard`, `NextDNS`) timed out vs `2/2` (`124 B` / `1280 B`) on VPN.
   - **`0/5` domain-SNI DoH** endpoints (`cloudflare-dns.com`, `dns.google`, `dns.quad9.net`, `dns.adguard-dns.com`, `dns.nextdns.io`) passed — all hit `curl (35) Connection reset by peer`.
   - **Takeaway:** Bare-IP DoH (`1.1.1.1`, `1.0.0.1`, `8.8.8.8`, `8.8.4.4` on `443/tcp`) bypasses UDP/TCP `53`, port `5353`, `853` DoT/DoQ filtering, and domain-SNI DoH resets.

---

## 3. Layer 2: DPI Signatures, Synthetic SNI Proof & `split_2b` Bypass

1. **Speed-of-Light & TTL Proof (`134` PCAP events in V3):**
   - `120 / 134` (`89.6%`) injected `TCP RST (Win=0)` packets carry `TTL=60`; `123` mismatch the origin `SYN-ACK` TTL; `130` arrive faster (`median 93.86 ms`, `min 36.67 ms`) than the server `SYN-ACK` (`median 183.87 ms`), giving one-sided Mann-Whitney **`p = 2.73e-34`**.
   - Plaintext HTTP port `80` injects `HTTP/1.1 403 Forbidden` (`Content-Length: 337`, `charset=windows-1256`, `<title>NSV2</title>`, `iframe src="http://10.10.34.36/?type=Invalid Keyword&policy=MainPolicy "`).
2. **Dual-Server Synthetic SNI Trap (`20` `probe-test-404.*` FQDNs):**
   - Sending non-existent SNIs to two independent control servers — **Hetzner DE (`78.46.170.2`)** and **Vultr DE (`108.61.210.117`)** — caused **`12/20`** (`pages.dev`, `netlify.app`, `workers.dev`, `digitaloceanspaces.com`, `herokuapp.com`, `firebaseapp.com`, `instagram.com`, `youtube.com`, `x.com`, `signal.org`, `telegram.org`, `bbc.com`) to reset on **both** servers and return `403 NSV2` on port `80`, while all `8` non-blacklisted patterns returned `TLS_SERVER_HELLO`.
3. **Upstream Geo-Block Separation:**
   - Destinations enforcing upstream geo/WAF blocks (`cloudflare.com`, `openai.com`, `api.openai.com`, `crates.io`, `gitlab.com`, `fastly.com`, `pkg.go.dev`, `anydesk.com`, `teamviewer.com`) complete `TLS_SERVER_HELLO` (origin TTL `46–52`) before returning `HTTP 403/421`.
4. **9-Shape `ClientHello` Evasion Matrix (`18` targets in V3):**
   - **Blocked (`TCP_RST_INJECTED`):** `normal`, `tls12`, `pad1800`, `ech_grease` (`0xfe0d`), `split_5b`, `split_midsni`.
   - **Bypassed (`TLS_SERVER_HELLO`):** **`split_2b`** (`10` hello / `1` RST), **`rec_split_2`** (`10` hello / `0` RST), and **`rec_split_5`** (`10` hello / `0` RST) restored handshakes across `pages.dev`, `fra1/ams3.digitaloceanspaces.com`, `gra/sbg.proof.ovh.net`, `x.com`, `discord.com`, and `signal.org`.

---

## 4. Layer 3/4: Cloud Reachability, Core Loops & Fastly `5,552 B` Stall

### Cloud & VPS Provider Matrix (`57` Endpoints in V3; `57/57` OK on VPN)

| Provider | V3 MCI Result | Practical Consequence |
| :--- | :--- | :--- |
| **Hetzner** | **`3 / 3` OK** | `78.46.170.2`, `95.217.255.81`, `78.47.119.196` clean (`6.16–21.92 Mbps` in V1) |
| **Vultr** | **`2 / 2` OK** | `108.61.210.117` (`15.71 Mbps`), `108.61.198.102` (`6.62 Mbps`) clean |
| **GitHub / Ubuntu Archive** | **`OK`** | `github.com` (`6.96 Mbps`), `archive.ubuntu.com` (`19.89 Mbps`) |
| **Linode (Akamai)** | **`1 / 6` OK (`5` Blackholed)** | L3/L4 `100%` drop on FRA (`139.162.130.8`), LON (`176.58.107.39`), NJ (`50.116.57.237`), SGP (`139.162.23.4`), TYO2 (`139.162.65.37`) |
| **DigitalOcean** | **`0 / 7` OK** | `167.99.240.1` & `www.digitalocean.com` L3/L4 Blackhole; all 5 Spaces (`fra1`/`ams3`/`nyc3`/`sgp1`/`sfo3`) DPI `RST` |
| **OVHcloud** | **`1 / 6` OK** | `141.95.207.211` & `51.38.45.1` L3/L4 Blackhole / Hop-30 loop (`4,219 ms`); `141.94.30.145` & `51.91.75.40` DPI `RST` |
| **Microsoft** | **`4 / 6` OK** | `150.171.109.71` stuck in Hop-30 core loop (`10.21.71.20 -> 10.21.211.11 -> 10.21.212.20 -> 10.21.212.21`); `20.112.52.29` Blackhole |
| **PaaS & Registries** | **Disrupted** | `pages.dev`, `netlify.app`, `herokuapp.com` (DPI RST); `fly.dev` (TLS timeout); `supabase.co`, `firebaseapp.com`, `hub.docker.com` (L3/L4 Blackhole) |

### Fastly `151.101.18.132` (`5,552 B` = `4 x 1388 B` MSS) Stall
- HTTP flows to Fastly POP **`151.101.18.132`** (`deb.debian.org`) stall after `5,552 B` (`Range: bytes=0-5553` succeeds, `0-6143` and `0-20479` stall with `17` server retransmissions).
- `146.75.78.132` (`deb.debian.org` / `dl-cdn.alpinelinux.org`) and `146.75.76.223` (`files.pythonhosted.org`) also timed out in V3.
- Healthy sibling POPs: **`146.75.118.132`** (`1.85 Mbps` HTTP / `1.39 Mbps` HTTPS), **`151.101.130.132`** (`1.76 Mbps` / `1.52 Mbps`), **`151.101.66.132`** (`1.56 Mbps` / `1.30 Mbps`), **`151.101.194.132`** (`security.debian.org`), and **`151.101.0.223`** (`pypi.org`).

### QUIC, NTP & PMTU
- **QUIC `v1` (`UDP/443`):** `42` outbound packets, `0` replies in V3 PCAP (`100%` drop).
- **NTP (`UDP/123`):** `time.google.com` (`216.239.35.4`) timed out while `time.cloudflare.com`, `ntp.ubuntu.com`, `ir.pool.ntp.org` answered.
- **PMTU & Baseline Jitter:** `1500 B` wire MTU (`1472 B` ICMP payload) with `0.05 ms` local gateway jitter stdev (`19.89 Mbps` on Ubuntu Archive), leaving clean margin for WireGuard `MTU = 1280`.
