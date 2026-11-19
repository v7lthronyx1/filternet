#!/usr/bin/env bash
set -u

CMD="${1:-status}"
OPT="${2:-}"

if [ "$CMD" = "help" ] || [ "$CMD" = "-h" ] || [ "$CMD" = "--help" ]; then
  printf 'Usage: fix-fastly-apt.sh <status|apply|revert> [--no-apt-ipv4]\n'
  exit 0
fi

HOSTS_FILE="/etc/hosts"
HOSTS_BAK="/etc/hosts.filternet.bak"
APT_CONF="/etc/apt/apt.conf.d/99-filternet-ipv4"
DEBIAN_POPS=("146.75.118.132" "151.101.130.132" "151.101.66.132")
SEC_POPS=("151.101.194.132" "151.101.130.132" "146.75.118.132")
PYPI_POPS=("151.101.0.223" "151.101.64.223" "151.101.130.132")

probe_debian_pop() {
  local ip="$1"
  local out
  out="$(curl -4 -sS --max-time 6 --resolve "deb.debian.org:80:$ip" -r 0-20479 -o /dev/null -w '%{http_code} %{size_download}' "http://deb.debian.org/debian/dists/stable/Release" 2>/dev/null || printf '000 0')"
  printf '%s' "$out"
}

probe_https_pop() {
  local host="$1"
  local ip="$2"
  local path="$3"
  local out
  out="$(curl -4 -sS --max-time 6 --resolve "$host:443:$ip" -o /dev/null -w '%{http_code} %{size_download}' "https://$host$path" 2>/dev/null || printf '000 0')"
  printf '%s' "$out"
}

pick_debian_pop() {
  local ip res code bytes
  for ip in "${DEBIAN_POPS[@]}"; do
    res="$(probe_debian_pop "$ip")"
    code="${res%% *}"
    bytes="${res##* }"
    if [ "$code" = "206" ] || [ "$code" = "200" ]; then
      if [ "${bytes:-0}" -ge 20000 ] 2>/dev/null; then
        printf '%s' "$ip"
        return 0
      fi
    fi
  done
  return 1
}

pick_https_pop() {
  local host="$1"
  local path="$2"
  shift 2
  local ip res code
  for ip in "$@"; do
    res="$(probe_https_pop "$host" "$ip" "$path")"
    code="${res%% *}"
    if [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ]; then
      printf '%s' "$ip"
      return 0
    fi
  done
  return 1
}

show_status() {
  local h res code bytes
  printf '=== Current DNS / Hosts Resolution ===\n'
  for h in deb.debian.org security.debian.org pypi.org; do
    printf '%-22s: %s\n' "$h" "$(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
  done

  printf '\n=== Active /etc/hosts Pins ===\n'
  grep -E '^[0-9.]+\s+(deb\.debian\.org|security\.debian\.org|pypi\.org)(\s|$)' "$HOSTS_FILE" 2>/dev/null || printf 'None\n'

  printf '\n=== APT IPv4 Config ===\n'
  if [ -f "$APT_CONF" ]; then
    cat "$APT_CONF"
  else
    printf 'Not installed (%s)\n' "$APT_CONF"
  fi

  printf '\n=== Fastly 20KB Range Probe (deb.debian.org) ===\n'
  for ip in 151.101.18.132 "${DEBIAN_POPS[@]}"; do
    res="$(probe_debian_pop "$ip")"
    code="${res%% *}"
    bytes="${res##* }"
    if [ "$ip" = "151.101.18.132" ] && [ "${bytes:-0}" -lt 20000 ] 2>/dev/null; then
      printf '%-16s -> HTTP %s, %s bytes (STALL DETECTED)\n' "$ip" "$code" "$bytes"
    elif [ "${bytes:-0}" -ge 20000 ] 2>/dev/null; then
      printf '%-16s -> HTTP %s, %s bytes (HEALTHY)\n' "$ip" "$code" "$bytes"
    else
      printf '%-16s -> HTTP %s, %s bytes (FAILED)\n' "$ip" "$code" "$bytes"
    fi
  done
}

require_root() {
  if [ "$EUID" -ne 0 ]; then
    exec sudo "$(readlink -f "$0")" "$@"
  fi
}

strip_managed_hosts() {
  local tmp
  tmp="$(mktemp)"
  awk '!/^[0-9.]+\s+(deb\.debian\.org|security\.debian\.org|pypi\.org)(\s|$)/' "$HOSTS_FILE" > "$tmp"
  cat "$tmp" > "$HOSTS_FILE"
  rm -f "$tmp"
}

do_apply() {
  require_root apply "$OPT"
  local deb_ip sec_ip pypi_ip
  printf 'Probing healthy Fastly POPs...\n'
  deb_ip="$(pick_debian_pop)" || {
    printf 'No healthy deb.debian.org POP passed 20KB range test.\n' >&2
    exit 1
  }
  sec_ip="$(pick_https_pop "security.debian.org" "/debian-security/dists/stable-security/Release" "${SEC_POPS[@]}")" || sec_ip="151.101.194.132"
  pypi_ip="$(pick_https_pop "pypi.org" "/" "${PYPI_POPS[@]}")" || pypi_ip="151.101.0.223"

  if [ ! -f "$HOSTS_BAK" ]; then
    cp -a "$HOSTS_FILE" "$HOSTS_BAK"
  fi
  strip_managed_hosts
  printf '%s deb.debian.org\n%s security.debian.org\n%s pypi.org\n' "$deb_ip" "$sec_ip" "$pypi_ip" >> "$HOSTS_FILE"

  if [ "$OPT" != "--no-apt-ipv4" ]; then
    mkdir -p /etc/apt/apt.conf.d
    printf 'Acquire::ForceIPv4 "true";\n' > "$APT_CONF"
  fi

  printf 'Applied Fastly mirror pins:\n'
  printf '  deb.debian.org      -> %s\n' "$deb_ip"
  printf '  security.debian.org -> %s\n' "$sec_ip"
  printf '  pypi.org            -> %s\n' "$pypi_ip"
}

do_revert() {
  require_root revert "$OPT"
  strip_managed_hosts
  rm -f "$APT_CONF"
  printf 'Reverted Fastly /etc/hosts pins and %s.\n' "$APT_CONF"
}

case "$CMD" in
  status) show_status ;;
  apply) do_apply ;;
  revert) do_revert ;;
  *)
    printf 'Unknown command: %s\nUsage: fix-fastly-apt.sh <status|apply|revert> [--no-apt-ipv4]\n' "$CMD" >&2
    exit 1
    ;;
esac
