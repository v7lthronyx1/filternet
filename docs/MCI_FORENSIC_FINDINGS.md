# MCI (AS197207) Multi-Session Forensic Findings

Packet-level measurements recorded across four sessions (`V1 -> V2 -> V3 -> V4`) on Hamrah-e-Avval / MCI (`AS197207`) over Wi-Fi hotspot (`wlan0`) and USB/Ethernet tethering (`eth0`), against isolated clean VPN baselines.

For automated 6-stage `dumpcap`/`tshark` capture and regulatory filing bundles (`195.cra.ir`), see the companion forensics suite **[shitnet](https://github.com/v7lthronyx1/shitnet)**.

---

## 1. Four-Session Progression (`V1 -> V2 -> V3 -> V4`)

| Metric | Audit V1 (`wlan0`) | Audit V2 (`wlan0`) | Audit V3 (`eth0`) | Audit V4 (`eth0`, 2026-11-24) |
| :--- | :--- | :--- | :--- | :--- |
| **Audited Prefix / Exit** | `5.213.x.x` (`AS197207`) | `95.64.x.x` (`AS197207`) | `178.131.x.x` (`178.131.192.0/20`) | `5.216.x.x` (`5.216.48.0/20`) |
| **Forged DPI `TCP RST` Events** | `76` (`64` at `TTL=60`; median `59.76 ms`) | `126` (`51` at `TTL=60`; median `44.86 ms`, `p=6.65e-34`) | `134` (`120` at `TTL=60 = 89.6%`; median `93.86 ms`, `p=2.73e-34`) | **`146`** (`129` at `TTL=60 = 88.4%`; median `53.74 ms`, **`p=7.49e-41`**) |
| **Cloud / CDN Endpoints Disrupted** | `13 / 32` (`40.6%`) | `25 / 57` (`43.9%`) | **`26 / 57` (`45.6%`)** vs `57/57` TCP OK on VPN | **`24 / 61` (`39.3%`)** vs `61/61` TCP OK on VPN |
| **Dual-Server Synthetic SNI Trap** | — | `10 / 18` reset (Hetzner) | **`12 / 20`** reset on **both** Hetzner & Vultr + `12/20` `403 NSV2` | **`12 / 20`** reset on **both** Hetzner & Vultr + `12/20` HTTP blockpage |
| **Core MPLS Routing Loops (`10.21.x.x`)** | `150.171.109.71` (Microsoft) | `150.171.109.71` (Hop 30) | Expanded to `141.95.207.211` (OVH, up to `4,219 ms`) + `150.171.109.71` | Expanded to `1.1.1.1` (Cloudflare), Fastly (`146.75.118.132` up to `7,284 ms`), Linode, DO & `150.171.109.71` (`7,209 ms`) |
| **`PortQuiz:51820` (TCP Control)** | `False` | `False` (`ConnectionRefused`) | `True` (`158.66 ms`) | `True` (`33/33` ports OK on `13.216.200.40`; legacy `35.180.86.68` unreachable) |
| **`Google-DL-5MB` Throughput** | `13.95 Mbps` | Degrading | **`0.24 Mbps`** (`660,793 B`, `rc=28`) | Recovered to **`6.96 Mbps`** (`5,242,880 B`, `rc=0`) |
| **Fastly `151.101.18.132` (`deb.debian.org`)** | Stalled above `5,552 B` | Stalled | Still stalled above `5,552 B` (`17` server retransmissions in PCAP) | Still stalled at `5,552 B` (`rc=28`; `6,230 B` in fastly stall probe) |

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

---

## Audit V4 Findings: DPI Tightening, Real ECH & Windscribe Infrastructure (2026-11-24)

Audit V4 (`eth0` bound directly via unprivileged `SO_BINDTODEVICE` on prefix `5.216.48.0/20`) shows significant DPI progression alongside fresh target-specific behavior:

1. **DNS Forgery & `HTTPS` (`Type 65`) Stripping:**
   - Across `122` domains, `31` failed DNS (`28` sinkholed to `10.10.34.x`, `2` SafeSearch redirects `216.239.38.120`, `1` private RFC1918 redirect).
   - `118` forged UDP DNS replies captured (`TTLs [60, 113, 114, 191, 192]`; forged median RTT `47.39 ms` vs clean `131.88 ms`), `16/18` external plain resolvers hijacked (`2` timed out), and `31/31` `HTTPS` (`Type 65`) records stripped (`0` returned by ISP vs `31` on clean VPN), blocking automatic browser ECH key discovery.
   - Standard DoT (`0/7`), domain DoH (`0/5`, all `TCP RST`), and DoQ (`0/2`) failed on ISP; **`PortQuiz` TCP ports `33/33` opened on `13.216.200.40`** while legacy `35.180.86.68` timed out.
   - Bare-IP DoH to Cloudflare (`1.1.1.1`, `1.0.0.1` `/dns-query`) and Google (`8.8.8.8`, `8.8.4.4` `/resolve`) returned `HTTP 200` for both `A` (`x.com`) and `HTTPS Type 65` (`crypto.cloudflare.com`, including real `ech=` config), whereas `9.9.9.9/dns-query?...` returned `HTTP 505`.

2. **DPI Escalation: `split_2b` Degrading vs `100%` `rec_split_2` / `rec_split_5`:**
   - `146` forged `TCP RST` events (`129/146 = 88.4%` at `TTL=60`; `140` arrived ahead of the real server; median `53.74 ms` vs `144.22 ms` server RTT, `p = 7.49e-41`).
   - Across `13` general targets in the V4 evasion matrix, `normal`, `tls12`, `pad1800` (large padding), `ech_grease` (`0xfe0d`), `split_5b`, and `split_midsni` suffered `13/13` resets.
   - **`split_2b` (TCP-level 2-byte segmentation) started breaking on high-enforcement targets**, hitting `TCP_RST_INJECTED` on `api.windscribe.com` (`104.20.1.154`), `x.com` (`filternet probe`), and `1` of `11` evasion matrix targets, whereas **TLS record-layer splitting (`rec_split_2` and `rec_split_5`) succeeded `100%` (`0` RST / `11` `TLS_SERVER_HELLO`)** in the matrix and bypassed DPI on every tested target.

3. **Windscribe Infrastructure, Real ECH & Custom SNI Behavior:**
   - Gateway DNS poisoned `windscribe.com` / `checkip.windscribe.com` (`10.10.34.36`) and timed out on `api.windscribe.com` / `assets.windscribe.com`; all resolved cleanly with `HTTPS` records via Bare-IP DoH `1.1.1.1`.
   - On `windscribe.com`, `api.windscribe.com`, and `assets.windscribe.com`, both `pad1800` (Large TLS) and `split_5b` triggered `TCP_RST_INJECTED` (`3/3`). `api.windscribe.com` also rejected `split_2b`, leaving **`rec_split_2` (`483.9 ms`) and `rec_split_5` (`524.9 ms`)** as the reliable TLS handshake bypasses across both primary domains and Cloudflare failover aliases (`totallyacdn.com`, `api.totallyacdn.com`, `staticnetcontent.com`, where `no_sni` failed with `TLS_ALERT_2_40`).
   - **Real Encrypted Client Hello (`ECH`):** With real `Type 65` keys supplied via Bare-IP DoH, `crypto.cloudflare.com`, `cloudflare.com`, and `defo.ie` all completed `TLS_SERVER_HELLO` (`100%` pass) over MCI `eth0`, whereas `ECH GREASE` alone received `TLS_ALERT_2_50`.
   - **Custom SNI Candidates (Dual Hetzner/Vultr Check):** `github.com`, `cloudflare.com`, `ubuntu.com`, `microsoft.com`, `apple.com`, and `workers.dev` completed clean handshakes on both servers even without splitting, while `pages.dev`, `netlify.app`, and `herokuapp.com` triggered `RST` under normal `ClientHello` and succeeded under `rec_split_2`.

4. **Cloud Reachability, Fastly & QUIC:**
   - `24/61` (`39.3%`) cloud endpoints disrupted (`Linode 1/6 OK`, `DigitalOcean 1/7 OK`, `OVH 1/5 OK`, `Microsoft 4/6 OK`), while `Hetzner (3/3)`, `Vultr (2/2)`, `GitHub (3/3)`, `LinuxRepo (6/6)`, and `Google (2/2)` remained reachable.
   - `Google-DL-5MB` throughput recovered to `6.96 Mbps` (`5,242,880 B`, `rc=0`) in V4, while Fastly `151.101.18.132` (`deb.debian.org`) continued stalling above `5,552 B` (`rc=28`) and sibling POPs `146.75.118.132` (`1.10 Mbps`) and `151.101.130.132` (`1.04 Mbps`) completed normally despite elevated `mtr` hop latencies (`6,039–7,284 ms`).
   - QUIC `UDP/443` showed `42` outbound / `0` inbound replies (`100%` drop), `time.google.com` (`UDP/123`) remained blocked, and PMTU held at `1500 B` with `0.06 ms` local gateway jitter stdev.
