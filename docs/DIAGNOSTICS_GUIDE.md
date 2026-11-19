# Diagnostics Guide

Run the cross-platform CLI from Windows, macOS, or Linux:
```bash
filternet doctor
filternet probe
```
Or run `./scripts/diagnose-vpn.sh` on Linux for NetworkManager, `ip rule`, `nft`, and Surfshark cache checks.

---

## Manual Verification Commands

### 1. DNS Hijacking (`53` & `5353`), SafeSearch, `HTTPS` RR, DoT & DoH
```bash
dig +short +time=2 +tries=1 @8.8.4.4 x.com
dig +short +time=2 +tries=1 @8.8.4.4 google.com
dig +short +time=2 +tries=1 -p 5353 @208.67.222.222 x.com
dig +short +time=2 +tries=1 @8.8.4.4 cloudflare.com HTTPS
dig +short +time=2 +tries=1 @127.0.2.1 cloudflare.com HTTPS
dig +tls +short +time=2 +tries=1 @1.1.1.1 example.com
curl -4 -sS --max-time 4 -H 'Accept: application/dns-json' 'https://1.1.1.1/dns-query?name=example.com&type=A'
curl -4 -sS --max-time 4 --resolve cloudflare-dns.com:443:104.16.248.249 -H 'Accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=example.com&type=A'
```
- `10.10.34.35` / `10.10.34.36` on port `53` or `-p 5353`: Active DNS hijacking.
- `216.239.38.120` for `google.com`: Forced SafeSearch injection.
- Empty `HTTPS` (Type 65) answer on external UDP/53 vs populated `alpn=`/`ech=` record on `dnscrypt-proxy`: Middlebox record stripping.
- `timed out` on DoT (`853`) and `curl (35) Connection reset by peer` on domain DoH (`cloudflare-dns.com`) while `https://1.1.1.1/dns-query` returns HTTP `200`: Confirms bare-IP DoH is the working path.

### 2. PortQuiz Control (`853` / `51820`) vs Protocol DPI
```bash
nc -zv -w 3 35.180.86.68 853 51820 443
```
- `portquiz.net:853` open while `DoT` (`853/tcp`) and `DoQ` (`853/udp`) fail indicates protocol-level DPI rather than a closed TCP port.
- `portquiz.net:51820` failing indicates UDP/TCP `51820` filtering on the current IP allocation.

### 3. DPI SNI Injection vs Upstream Geo-Block (`split_2b`)
```bash
curl -Iv --max-time 6 --resolve cloudflare.com:443:104.16.132.229 https://cloudflare.com/ -o /dev/null
filternet probe
```
- `Connection reset by peer` before `TLS_SERVER_HELLO` (plus `probe-test-404.pages.dev` failing against `78.46.170.2` / `108.61.210.117` and HTTP port `80` returning `403 NSV2`) proves mid-path DPI.
- `TLS_SERVER_HELLO` followed by `HTTP 403` / `421` (`cloudflare.com`, `openai.com`, `crates.io`) indicates upstream destination WAF/geo-blocking.

### 4. Fastly `151.101.18.132` (`5,552 B` Stall)
```bash
filternet hosts-pin status
```
- `0-4095` succeeding (`4096 B`) while `0-20479` stalls at `5552 B` on `151.101.18.132` (and completes `20480 B` on `146.75.118.132` / `151.101.130.132`) confirms the Fastly stall. Fix with `filternet hosts-pin apply`.

### 5. Cloud Blackholes, `MTR` Core Loops & `PMTU`
```bash
mtr -rn -c 5 150.171.109.71
mtr -rn -c 5 141.95.207.211
```
- Repeated private hops (`10.21.212.x`, `10.71.111.x`, `10.160.x.x`) reaching Hop 30 indicate ISP core routing loops.
- `filternet probe` compares Hetzner and Vultr against Linode, DigitalOcean, and OVH directly.

### 6. Full PCAP-Backed Regulatory Evidence (`shitnet`)
For `dumpcap`/`tshark` PCAP captures, `Mann-Whitney U` testing, charts, and `195.cra.ir` complaint PDFs, run **[shitnet](https://github.com/v7lthronyx1/shitnet)**.
