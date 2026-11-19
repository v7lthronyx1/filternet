# FilterNet (فیلترنت)

ابزار چندسکویی تشخیص فیلترینگ اینترنت، پروفیل‌های DNS رمزنگاری‌شده، رفع قفل مخازن روی Fastly و بهینه‌سازی WireGuard برای **Windows**، **macOS** و **Linux**

ساخته‌شده توسط **Aiden Azad** — **[V7lthronyx](https://github.com/v7lthronyx1)**

> [English Documentation (README.md)](README.md)

---

## چرا FilterNet؟

ممیزی‌های سطح بسته (`PCAP`) روی اینترنت همراه اول (`AS197207` — جزئیات کامل در [docs/MCI_FORENSIC_FINDINGS.md](docs/MCI_FORENSIC_FINDINGS.md)) نشان داد اختلال‌های روزمره در VPN، دانلودها و مدیریت پکیج‌ها ریشه مشخص و قابل تکرار دارند:

1. **ربایش DNS روی پورت `53` و `5353` و حذف رکورد `HTTPS`:** هر دو پورت `53` و غیرمتعارف `5353` (UDP/TCP) به آی‌پی‌های مسموم (`10.10.34.36`، SafeSearch `216.239.38.120` یا `10.110.10.1`) هدایت می‌شوند و `30/30` رکورد `HTTPS/SVCB` حذف می‌گردد.
2. **بسته بودن `DoT`، `DoQ` و `DoH` دامنه‌ای:** با وجود باز بودن `portquiz.net:853`، پروتکل‌های `DoT (853/tcp)` (`0/7`)، `DoQ (853/udp)` (`0/2`) و `DoH` مبتنی بر دامنه (`0/5`) قطع می‌شوند و تنها **DoH مبتنی بر IP خالص (`1.1.1.1`، `1.0.0.1`، `8.8.8.8`، `8.8.4.4` روی `443/tcp`)** پایدار کار می‌کند.
3. **الگوی DPI (`TTL=60` و `NSV2`) و بایپس `split_2b`:** حتی دامنه‌های ساختگی ناموجود (`probe-test-404.*`) روی دو سرور مستقل آلمان (`Hetzner` و `Vultr`) با `TCP RST` (`p = 2.73e-34`) و صفحه `403 NSV2` قطع می‌شوند. حالت‌های `tls12`، `pad1800` و `ech_grease` مسدودند و تنها **`split_2b`** و **`rec_split_2`/`5`** عبور می‌کنند؛ همچنین `QUIC v1 (UDP/443)` با `100%` ریزش همراه است.
4. **قفل شدن مخازن روی Fastly `151.101.18.132` (بایت `5552`):** دریافت از `deb.debian.org` روی نود `151.101.18.132` دقیقاً پس از `5,552` بایت قفل می‌شود، در حالی که نودهای هم‌خانواده سالم (`146.75.118.132`، `151.101.130.132`، `151.101.66.132`، `151.101.194.132` و `151.101.0.223`) با سرعت کامل دانلود می‌شوند.
5. **اختلال سرورهای ابری و تنظیمات WireGuard:** `45.6%` (`26/57`) اندپوینت‌های ابری روی همراه اول مختل بودند (`Linode`، `DigitalOcean`، `OVH` و حلقه `10.21.212.x` برای `Microsoft 150.171.109.71`)، در حالی که `Hetzner`، `Vultr`، `Cloudflare`، `GitHub` و `Ubuntu Archive` سالم‌اند. کانفیگ‌های WireGuard برای کارکرد پایدار نیازمند `MTU = 1280`، `PersistentKeepalive = 25`، حذف خط `DNS =` متداخل و رزولوشن IP از طریق DoH هستند.

برای کپچر خودکار `dumpcap`/`tshark` و تولید فایل‌های PDF شکایت رگولاتوری (`۱۹۵`) از پروژه مکمل **[shitnet](https://github.com/v7lthronyx1/shitnet)** استفاده کنید.

---

## شروع سریع روی Windows، macOS و Linux

ابزار اصلی بدون هیچ پکیج اضافه‌ای و صرفاً با کتابخانه استاندارد **Python 3.9+** اجرا می‌شود.

اجرای مستقیم بدون نصب:
```bash
git clone https://github.com/v7lthronyx1/filternet.git
cd filternet
python3 -m filternet doctor
```

یا نصب به‌صورت دستور سراسری `filternet`:
```bash
pip install .
```

### دستورات مشترک روی هر سه سیستم‌عامل

- **بررسی سریع وضعیت شبکه، DNS، Fastly و PMTU (فقط‌خواندنی):**
  ```bash
  filternet doctor
  ```
- **اسکن فعال DNS (`53`/`5353`)، تله SNI، بایپس `split_2b`، قفل Fastly و وضعیت سرورهای ابری:**
  ```bash
  filternet probe
  filternet probe --quick --json
  ```
- **بررسی و پین‌کردن آی‌پی‌های سالم Fastly در فایل `hosts` سیستم (با دسترسی Admin / `sudo`):**
  ```bash
  filternet hosts-pin status
  filternet hosts-pin apply
  filternet hosts-pin revert
  ```
- **بهینه‌سازی هر فایل کانفیگ WireGuard (`MTU = 1280`، `Keepalive = 25`، رزولوشن Endpoint با DoH و حذف DNS متداخل):**
  ```bash
  filternet wg-prepare raw-profile.conf -o clean-profile.conf
  ```
- **تولید فایل تنظیم `dnscrypt-proxy` با DoH مبتنی بر IP خالص:**
  ```bash
  filternet dns-config --target crossplatform -o dnscrypt-proxy.toml
  ```

راهنمای گام‌به‌گام برای هر سیستم‌عامل در [docs/CROSS_PLATFORM_GUIDE.md](docs/CROSS_PLATFORM_GUIDE.md) قرار دارد.

---

## اسکریپت‌های تکمیلی لینوکس

- [scripts/diagnose-vpn.sh](scripts/diagnose-vpn.sh): بررسی خواندنی NetworkManager، بریج‌های یتیم `172.20.0.0/16`، قوانین `ip rule`/`nft`، کش Surfshark، وضعیت `5353`/`HTTPS RR`/`PortQuiz`/Fastly و `PMTU`.
- [scripts/ss-wg](scripts/ss-wg): پاک‌سازی تداخل‌های سیستمی و چرخش خودکار اندپوینت‌های WireGuard (`fix-system`، `up [phx|lax|<profile>|/path/to/conf] [--force]`، `down`، `clean`، `status`).
- [scripts/fix-fastly-apt.sh](scripts/fix-fastly-apt.sh): تست ۲۰ کیلوبایتی، پین‌کردن نودهای سالم Fastly در `/etc/hosts` و تنظیم `Acquire::ForceIPv4 "true";` برای APT (`status`، `apply`، `revert`).
- [scripts/probe-filtering.py](scripts/probe-filtering.py): اجرای مستقیم ماژول `filternet probe`.

---

## ساختار مخزن

- `filternet/`: پکیج چندسکویی Python 3.9+ (`cli.py`، `net_os.py`، `dns_raw.py`، `dpi.py`، `fastly.py`، `hosts_mgr.py`، `wg_conf.py`)
- `configs/dnscrypt-proxy/`: کانفیگ `dnscrypt-proxy-crossplatform.toml` (`127.0.0.1:53`)، `dnscrypt-proxy.toml` (`systemd`) و `resolved.conf`
- `configs/wireguard/`: نمونه بدون کلید `surfshark-wg.conf.example`
- `configs/NetworkManager/`: فایل `90-ss-wg-unmanaged.conf`
- `configs/hosts/` و `configs/apt/`: فایل‌های مرجع `fastly-healthy-mirrors.hosts` و `99-filternet-ipv4.conf`
- `docs/`: [CROSS_PLATFORM_GUIDE.md](docs/CROSS_PLATFORM_GUIDE.md)، [MCI_FORENSIC_FINDINGS.md](docs/MCI_FORENSIC_FINDINGS.md)، [TIMELINE_AND_FIXES.md](docs/TIMELINE_AND_FIXES.md)، [DIAGNOSTICS_GUIDE.md](docs/DIAGNOSTICS_GUIDE.md)
- `scripts/`: اسکریپت‌های لینوکس و رانر خط فرمان
- `tests/`: تست‌های واحد آفلاین (`python -m unittest discover -s tests -v`)

---

## مجوز انتشار

منتشرشده تحت لایسنس **MIT** — **Aiden Azad (V7lthronyx)**
