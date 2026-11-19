# Contributing

Pull requests, bug reports, and multi-ISP probe results are welcome at [github.com/v7lthronyx1/filternet](https://github.com/v7lthronyx1/filternet).

## Testing Locally

Run the offline test suite (zero external dependencies):
```bash
python -m unittest discover -s tests -v
```

## Guidelines

1. Keep `filternet/` pure Python 3.9+ standard library (`dependencies = []` in `pyproject.toml`) so `doctor`, `probe`, `hosts-pin`, `wg-prepare`, and `dns-config` run without `pip install` on Windows, macOS, and Linux.
2. Never commit real WireGuard `PrivateKey` values, `*.conf` profiles, `*.ovpn` files, `*.pcapng` captures, `cache.json`, local LAN/gateway IPs, or subscriber public IPs.
3. Keep cross-platform paths and commands OS-aware via `filternet.net_os.get_os()`.
4. Document any new ISP probe findings with exact target IP, port, protocol, and observed error/outcome.
