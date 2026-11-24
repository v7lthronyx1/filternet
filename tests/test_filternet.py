import pathlib
import socket
import struct
import tempfile
import tokenize
import unittest
from filternet import APP_NAME, AUTHOR, BRAND, REPO_URL
from filternet.cli import build_parser, main, summarize_findings
from filternet.dns_raw import build_dns_query, classify_dns_verdict, encode_dns_name, parse_dns_reply
from filternet.dpi import build_client_hello, classify_tls_bytes
from filternet.hosts_mgr import apply_pins, read_managed_pins, revert_pins
from filternet.wg_conf import prepare_wg_config

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestFilterNetOffline(unittest.TestCase):
    def test_brand_metadata(self):
        self.assertEqual(APP_NAME, "FilterNet")
        self.assertEqual(BRAND, "V7lthronyx")
        self.assertEqual(AUTHOR, "Aiden Azad")
        self.assertIn("v7lthronyx1/filternet", REPO_URL)

    def test_no_comments_in_code_or_configs(self):
        for folder in ("filternet", "scripts", "configs", "tests"):
            base = REPO_ROOT / folder
            for p in sorted(base.rglob("*")):
                if not p.is_file() or "__pycache__" in p.parts:
                    continue
                if p.suffix == ".py":
                    with p.open("rb") as f:
                        toks = [t for t in tokenize.tokenize(f.readline) if t.type == tokenize.COMMENT and t.start[0] > 1]
                        self.assertEqual(toks, [], f"Comment found in {p}: {toks}")
                else:
                    for idx, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                        if idx == 1 and line.startswith("#!"):
                            continue
                        self.assertFalse(line.lstrip().startswith("#"), f"Comment found in {p}:{idx}: {line}")

    def test_dns_wire_roundtrip_and_verdict(self):
        q = build_dns_query("example.com", rtype_code=1, txid=0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        qname = encode_dns_name("example.com")
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
        question = qname + struct.pack("!HH", 1, 1)
        ans_a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120, 4) + socket.inet_aton("10.10.34.36")
        ans_https = b"\xc0\x0c" + struct.pack("!HHIH", 65, 1, 120, 3) + b"\x00\x01\x00"
        parsed = parse_dns_reply(header + question + ans_a + ans_https)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["ips"], ["10.10.34.36"])
        self.assertEqual(parsed["https_rr"], 1)
        self.assertTrue(classify_dns_verdict(parsed).startswith("SINKHOLE"))

        safe = {"ok": True, "ips": ["216.239.38.120"]}
        self.assertTrue(classify_dns_verdict(safe).startswith("FORCED_SAFESEARCH"))
        priv = {"ok": True, "ips": ["10.110.10.1"]}
        self.assertTrue(classify_dns_verdict(priv).startswith("PRIVATE_HIJACK"))
        clean = {"ok": True, "ips": ["104.16.132.229"]}
        self.assertEqual(classify_dns_verdict(clean), "OK (104.16.132.229)")

    def test_client_hello_and_tls_classifier(self):
        ch_norm = build_client_hello("x.com")
        self.assertEqual(ch_norm[0], 0x01)
        self.assertIn(b"x.com", ch_norm)

        ch_ech = build_client_hello("x.com", grease_ech=True)
        self.assertIn(b"\xfe\x0d", ch_ech)

        ch_pad = build_client_hello("x.com", pad_to=1800)
        self.assertGreaterEqual(len(ch_pad), 1750)

        self.assertEqual(classify_tls_bytes(b""), "EOF_CLOSE")
        self.assertEqual(classify_tls_bytes(b"\x16\x03\x03\x00\x05\x02\x00"), "TLS_SERVER_HELLO")
        self.assertEqual(classify_tls_bytes(b"\x15\x03\x03\x00\x02\x02\x32"), "TLS_ALERT_2_50")
        self.assertEqual(classify_tls_bytes(b"HTTP/1.1 403 Forbidden\r\n"), "RAW_HTTP_HTTP/1.1 403 Forbidden")

    def test_wg_conf_prepare(self):
        raw = (
            "[Interface]\n"
            "PrivateKey = PRIVKEY123\n"
            "Address = 10.14.0.2/16\n"
            "DNS = 162.252.172.57\n\n"
            "[Peer]\n"
            "PublicKey = PUBKEY456\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "Endpoint = de-fra.example.net:51820\n"
        )
        res = prepare_wg_config(raw, mtu=1280, keepalive=25, drop_dns=True, resolve_fn=lambda _h: ["89.187.187.73"])
        out = res["text"]
        self.assertNotIn("162.252.172.57", out)
        self.assertIn("MTU = 1280", out)
        self.assertIn("PersistentKeepalive = 25", out)
        self.assertIn("Endpoint = 89.187.187.73:51820", out)
        self.assertIn("PrivateKey = PRIVKEY123", out)

    def test_hosts_mgr_apply_and_revert(self):
        with tempfile.TemporaryDirectory() as td:
            hosts_file = pathlib.Path(td) / "hosts"
            apt_file = pathlib.Path(td) / "99-filternet-ipv4"
            hosts_file.write_text("127.0.0.1 localhost\n151.101.18.132 deb.debian.org\n", encoding="utf-8")

            apply_pins(
                {"deb.debian.org": "146.75.118.132", "pypi.org": "151.101.0.223"},
                hosts_path=hosts_file,
                install_apt_ipv4=True,
                apt_conf_path=apt_file,
            )
            self.assertTrue((pathlib.Path(td) / "hosts.filternet.bak").exists())
            pins = read_managed_pins(hosts_path=hosts_file)
            self.assertEqual(pins, [("deb.debian.org", "146.75.118.132"), ("pypi.org", "151.101.0.223")])
            self.assertIn("127.0.0.1 localhost", hosts_file.read_text(encoding="utf-8"))

            revert_pins(hosts_path=hosts_file, apt_conf_path=apt_file)
            self.assertEqual(read_managed_pins(hosts_path=hosts_file), [])
            self.assertIn("127.0.0.1 localhost", hosts_file.read_text(encoding="utf-8"))

    def test_cli_wg_prepare_and_dns_config(self):
        parser = build_parser()
        args = parser.parse_args(["probe", "--quick", "--json"])
        self.assertEqual(args.cmd, "probe")
        self.assertTrue(args.quick)
        self.assertTrue(args.json)

        with tempfile.TemporaryDirectory() as td:
            out_toml = pathlib.Path(td) / "dnscrypt.toml"
            rc = main(["dns-config", "--target", "crossplatform", "-o", str(out_toml)])
            self.assertEqual(rc, 0)
            txt = out_toml.read_text(encoding="utf-8")
            self.assertIn("127.0.0.1:53", txt)
            self.assertIn("sdns://", txt)

    def test_plain_language_summary_findings(self):
        doc_bad = {
            "udp53_8844_probe": {"ok": True, "ips": ["10.10.34.36"]},
            "doh_ip_1111": {"ok": True},
            "doh_domain_cf": {"ok": False},
            "fastly": {
                "151.101.18.132_20k": {"bytes": 5552},
                "146.75.118.132_20k": {"bytes": 20480},
            },
            "pmtu_1500_ok": True,
        }
        tips = summarize_findings(doc_rep=doc_bad)
        joined = " ".join(tips)
        self.assertIn("dns-config", joined)
        self.assertIn("hosts-pin apply", joined)

        probe_rec = {
            "dns": {},
            "protocols": {"doh_ip_1111": {"ok": True}, "doh_domain_cf": {"ok": False}},
            "dpi": {
                "x_normal": {"ok": False},
                "x_split_2b": {"ok": False},
                "x_rec_split_2": {"ok": True},
                "synthetic_hetzner_404": {"ok": False},
                "synthetic_hetzner_ctrl": {"ok": True},
            },
            "fastly": {
                "151.101.18.132_20k": {"bytes": 20480},
                "146.75.118.132_20k": {"bytes": 20480},
            },
        }
        probe_tips = " ".join(summarize_findings(probe_rep=probe_rec))
        self.assertIn("rec_split_2", probe_tips)
        self.assertIn("keyword filtering", probe_tips)


if __name__ == "__main__":
    unittest.main()
