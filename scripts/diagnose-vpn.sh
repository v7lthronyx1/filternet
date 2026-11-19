#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

printf '=== 1. Active Interfaces ===\n'
ip -br addr | grep -vE '^(br-|docker|lxcbr|veth|lo )' || true

printf '\n=== 2. Default Routes & Tunnel Stats ===\n'
ip -4 route show default || true
for dev in ss-wg ss-phx ss-lax surfshark_tun tun0 utun420; do
  if ip link show "$dev" >/dev/null 2>&1; then
    ip -s link show "$dev"
  fi
done

printf '\n=== 3. IP Rules ===\n'
ip -4 rule show

printf '\n=== 4. DNS & dnscrypt-proxy ===\n'
cat /etc/resolv.conf 2>/dev/null || true
lsattr /etc/resolv.conf 2>/dev/null || true
printf 'dnscrypt-proxy.service: %s\n' "$(systemctl is-active dnscrypt-proxy.service 2>/dev/null || true)"
printf 'dnscrypt-proxy.socket: %s\n' "$(systemctl is-active dnscrypt-proxy.socket 2>/dev/null || true)"

printf '\n=== 5. DNS Poisoning / 5353 / HTTPS RR / DoT / DoH Check ===\n'
printf 'Plain UDP @8.8.8.8 (ext2.surfshark.com): '
dig +short +time=2 +tries=1 @8.8.8.8 ext2.surfshark.com 2>/dev/null | tr '\n' ' ' || true
printf '\nPlain UDP @8.8.4.4 (x.com): '
dig +short +time=2 +tries=1 @8.8.4.4 x.com 2>/dev/null | tr '\n' ' ' || true
printf '\nPlain UDP @8.8.4.4 (google.com SafeSearch): '
dig +short +time=2 +tries=1 @8.8.4.4 google.com 2>/dev/null | tr '\n' ' ' || true
printf '\nNon-std Port 5353 @208.67.222.222 (x.com): '
dig +short +time=2 +tries=1 -p 5353 @208.67.222.222 x.com 2>/dev/null | tr '\n' ' ' || true
printf '\nLocal @127.0.2.1 (ext2.surfshark.com): '
dig +short +time=2 +tries=1 @127.0.2.1 ext2.surfshark.com 2>/dev/null | tr '\n' ' ' || true
printf '\nHTTPS RR Type65 @8.8.4.4 (cloudflare.com): '
dig +short +time=2 +tries=1 @8.8.4.4 cloudflare.com HTTPS 2>/dev/null | tr '\n' ' ' || printf 'EMPTY'
printf '\nHTTPS RR Type65 @127.0.2.1 (cloudflare.com): '
dig +short +time=2 +tries=1 @127.0.2.1 cloudflare.com HTTPS 2>/dev/null | tr '\n' ' ' || printf 'EMPTY'
printf '\nDoT @1.1.1.1:853: '
dig +tls +short +time=2 +tries=1 @1.1.1.1 ext2.surfshark.com 2>/dev/null | tr '\n' ' ' || true
printf '\nDoH @1.1.1.1:443 (bare-IP): '
curl -4 -sS --max-time 3 -H 'Accept: application/dns-json' -o /dev/null -w '%{http_code}' 'https://1.1.1.1/dns-query?name=example.com&type=A' 2>/dev/null || printf 'ERR'
printf '\nDoH @cloudflare-dns.com:443 (domain SNI): '
curl -4 -sS --max-time 3 --resolve cloudflare-dns.com:443:104.16.248.249 -H 'Accept: application/dns-json' -o /dev/null -w '%{http_code}' 'https://cloudflare-dns.com/dns-query?name=example.com&type=A' 2>/dev/null || printf 'RESET/ERR'
printf '\n'

printf '\n=== 6. Orphan 172.20.0.0/16 Bridges ===\n'
ip -4 route show | grep -E '172\.20\.' || printf 'None\n'

printf '\n=== 7. Conflicting Services & NM Configs ===\n'
printf 'expressvpn-service: %s\n' "$(systemctl is-active expressvpn-service 2>/dev/null || true)"
printf 'surfsharkd2: %s\n' "$(systemctl is-active surfsharkd2 2>/dev/null || true)"
if [ -e /etc/NetworkManager/dispatcher.d/99-vpn-route ]; then
  ls -l /etc/NetworkManager/dispatcher.d/99-vpn-route
fi
ls -1 /etc/NetworkManager/conf.d 2>/dev/null || true

printf '\n=== 8. Surfshark Cache Poison Check ===\n'
SS_CACHE="${HOME}/.config/Surfshark/cache.json"
if [ -f "$SS_CACHE" ]; then
  POISONED="$(grep -o '"10\.10\.34\.[0-9]*"' "$SS_CACHE" | head -n 10 || true)"
  if [ -n "$POISONED" ]; then
    printf '%s\n' "$POISONED"
  else
    printf 'Clean (no 10.10.34.x entries)\n'
  fi
else
  printf 'No Surfshark cache.json found\n'
fi

printf '\n=== 9. Connectivity & PMTU Check (1.1.1.1) ===\n'
curl -sI --max-time 4 https://1.1.1.1 | head -n 3 || printf 'Timeout or failed\n'
if ping -n -M do -s 1472 -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
  printf 'PMTU 1500B (1472+28): OK\n'
else
  printf 'PMTU 1500B (1472+28): Fragmented or blocked\n'
fi

printf '\n=== 10. PortQuiz Control Check (853 / 51820) ===\n'
for p in 443 853 51820; do
  if timeout 2 bash -c "exec 3<>/dev/tcp/35.180.86.68/$p" 2>/dev/null; then
    printf 'portquiz.net:%s -> OPEN\n' "$p"
  else
    printf 'portquiz.net:%s -> BLOCKED/TIMEOUT\n' "$p"
  fi
done

printf '\n=== 11. Fastly / Debian Mirror 5552B Stall Check ===\n'
printf 'deb.debian.org resolved IPs: %s\n' "$(getent ahostsv4 deb.debian.org 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
grep -E '^[0-9.]+\s+(deb\.debian\.org|security\.debian\.org|pypi\.org)(\s|$)' /etc/hosts 2>/dev/null || printf 'No /etc/hosts mirror pins\n'
for ip in 151.101.18.132 146.75.118.132; do
  res="$(curl -4 -sS --max-time 4 --resolve "deb.debian.org:80:$ip" -r 0-20479 -o /dev/null -w '%{http_code} %{size_download}' 'http://deb.debian.org/debian/dists/stable/Release' 2>/dev/null || printf '000 0')"
  printf 'deb.debian.org via %-15s (20KB range): HTTP %s, %s bytes\n' "$ip" "${res%% *}" "${res##* }"
done

printf '\n=== 12. Forensic Tools ===\n'
for bin in dumpcap tshark mtr python3 shitnet; do
  printf '%-12s: %s\n' "$bin" "$(command -v "$bin" 2>/dev/null || printf 'not found')"
done
if [ -x "$SCRIPT_DIR/probe-filtering.py" ]; then
  printf 'probe-filtering.py: %s\n' "$SCRIPT_DIR/probe-filtering.py"
fi
