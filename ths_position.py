#!/usr/bin/env python3
"""ths-position — Position query for THS Investment Ledger (read-only).

Python API and CLI in one file. All flows verified against the live service:
  credential login (verify2: RSA pubkey -> unified_login -> mainverify ->
  docookie2 -> session exchange) or SMS code login
  -> bound broker accounts -> per-account position snapshot
Dependencies: requests, cryptography
"""
import base64
import json
import os
import random
import string
import sys
import time

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

GATEWAY = "https://capital.hexin.cn/caishen_httpserver/passthrough"
AUTH_BASE = "https://auth.10jqka.com.cn/verify2"
UPASS_COOKIE = "https://upass.10jqka.com.cn/docookie2.php"
APP_VERSION = "4.46.0"
UA = "okhttp/4.9.3"
IV = b"0392039203920300"
WRAP_PUB = (  # wraps the session key (envelope "key" field)
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmpIVZxolaMuPQwsgFCZhLBEzK"
    "0+S/TysP8fuOqWl7mo4KmN7ovcnP8jHAFZhEDJvHhiKKsoWPdK1Mweo8jny8dWPF"
    "WYmuVOaUMeKEn5mwNj1xpzHsptFAJJ71IOzXczraXLtHmsfJcnYfCjoDrn9WCp1k"
    "Dqrg/AYuzBflKNVHSwIDAQAB"
)


class ThsPositionClient:
    def __init__(self, state_path="ths_position_state.json"):
        self.state_path = state_path
        self.state = json.load(open(state_path)) if os.path.exists(state_path) else {}

    # ---------- state (session key and device fingerprint must stay stable) ----------

    def _save(self, **kv):
        self.state.update(kv)
        fd = os.open(self.state_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.state, f, ensure_ascii=False, indent=1)

    def _key(self):
        if "key" not in self.state:
            self._save(key="".join(random.choices(string.ascii_lowercase + string.digits, k=16)))
        return self.state["key"]

    def _device(self):
        if "device" not in self.state:
            self._save(device={
                "imei": "".join(random.choices(string.digits, k=15)),
                "imsi": "".join(random.choices(string.digits, k=15)),
                "mac": ":".join(f"{random.randrange(256):02x}" for _ in range(6)),
                "devicename": "Pixel 7", "osversion": "14"})
        d = self.state["device"]
        return d, d["imei"] + d["imsi"] + d["mac"]

    # ---------- request envelope ----------

    @staticmethod
    def _aes_enc(key, text):
        p = PKCS7(128).padder()
        data = p.update(text.encode()) + p.finalize()
        e = Cipher(algorithms.AES(key.encode()), modes.CBC(IV)).encryptor()
        return base64.b64encode(e.update(data) + e.finalize()).decode()

    @staticmethod
    def _aes_dec(key, b64):
        d = Cipher(algorithms.AES(key.encode()), modes.CBC(IV)).decryptor()
        out = d.update(base64.b64decode(b64)) + d.finalize()
        u = PKCS7(128).unpadder()
        return (u.update(out) + u.finalize()).decode()

    @staticmethod
    def _rsa_wrap(pub_pem_or_spki, text):
        if b"BEGIN" in pub_pem_or_spki[:40].encode():
            pub = serialization.load_pem_public_key(pub_pem_or_spki.encode())
        else:
            pub = serialization.load_der_public_key(base64.b64decode(pub_pem_or_spki))
        return base64.b64encode(pub.encrypt(text.encode(), apad.PKCS1v15())).decode()

    def call(self, url_route, body, encrypt_type=2, key_type=0):
        key = self._key()
        _, dev = self._device()
        pp = self.state.get("passport", {})
        payload = dict(body)
        payload.setdefault("userid", pp.get("userid", ""))
        payload.setdefault("clienttime", int(time.time() * 1000))
        payload.setdefault("device", dev)
        payload.setdefault("terminal", "6")     # required inside the encrypted body
        payload.setdefault("version", APP_VERSION)
        if pp.get("utag"):
            payload.setdefault("utag", pp["utag"])
        form = {"token": pp.get("token", ""), "encrypt": str(encrypt_type),
                "param": self._aes_enc(key, json.dumps(payload, ensure_ascii=False, separators=(",", ":"))),
                "url": url_route, "userid": pp.get("userid", "") if pp.get("userid") else "0",
                "device": dev, "terminal": "6", "version": APP_VERSION, "key_type": str(key_type)}
        if encrypt_type in (2, 4) and key_type == 1:
            form["key"] = self._rsa_wrap(WRAP_PUB, key)
        r = requests.post(GATEWAY, data=form, timeout=30, headers={"User-Agent": UA})
        r.raise_for_status()
        env = r.json()
        if env.get("error_code", "-600") != "0":
            return {"error_code": env.get("error_code"), "error_msg": env.get("error_msg", "")}
        if str(env.get("encrypt", "0")) == "0":
            return env.get("ex_data")
        plain = self._aes_dec(key, env["ex_string"])
        return json.loads(plain)

    # ---------- credential login (4-step auth -> session exchange) ----------

    @staticmethod
    def _fix_pem(flat):
        # PEM newlines inside an XML attribute are collapsed to spaces; restore them
        body = (flat.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace(" ", "").replace("\n", ""))
        lines = [body[i:i + 64] for i in range(0, len(body), 64)]
        return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"

    def login_password(self, username, password):
        import xml.etree.ElementTree as ET
        s = requests.Session()
        s.headers["User-Agent"] = UA

        def verify2(params, step):
            r = s.get(AUTH_BASE, params=params, timeout=15)
            r.raise_for_status()
            root = ET.fromstring(r.text)
            ret = root.find("ret")
            if ret is None or ret.attrib.get("code") != "0":
                raise RuntimeError(f"{step} failed: {r.text[:200]}")
            return root.find("item")

        # 1. RSA public key (needs newline repair)
        item = verify2({"reqtype": "do_rsa", "type": "get_pubkey"}, "public key")
        pem = self._fix_pem(item.attrib["pubkey"])
        rsa_version = item.attrib.get("rsa_version", "default_5")
        # 2. unified login (credentials RSA-encrypted)
        item = verify2({"reqtype": "unified_login",
                        "account": self._rsa_wrap(pem, username),
                        "passwd": self._rsa_wrap(pem, password),
                        "msg": "1", "rsa_version": rsa_version,
                        "ta_appid": "2022021114090152"}, "login")
        userid, sessionid = item.attrib["userid"], item.attrib["sessionid"]
        # 3. mainverify -> signvalid
        item = verify2({"reqtype": "mainverify", "userid": userid, "sessionid": sessionid,
                        "qsid": "8003", "product": "S01", "version": "11.4.1.3",
                        "imei": "ZjI6MDY6NGE6NzI6MjQ6NTA=", "sdsn": "",
                        "rsa_version": rsa_version, "nohqlist": "0",
                        "securities": "%E5%90%8C%E8%8A%B1%E9%A1%BA%E8%BF%9C%E8%88%AA%E7%89%88"}, "mainverify")
        pp_map = dict(kv.split("=", 1) for kv in item.attrib["passport"].split("|") if "=" in kv)
        signvalid = pp_map["signvalid"]
        # 4. docookie2 -> cookies (ticket/user/u_name/userid)
        s.get(UPASS_COOKIE, params={"userid": userid, "sessionid": sessionid,
                                    "signvalid": signvalid}, timeout=15)
        ck = s.cookies.get_dict()
        # 5. exchange cookies for a gateway session
        out = self.call("1000:localhost", {
            "ticket": ck.get("ticket", ""), "user": ck.get("user", ""),
            "u_name": ck.get("u_name", ""), "userid": ck.get("userid", userid),
            "deviceinfo": self._device()[0], "type": "cookie"}, encrypt_type=4, key_type=1)
        pp = (out or {}).get("passport") or {}
        if not pp.get("token"):
            raise RuntimeError(f"session exchange failed: {json.dumps(out, ensure_ascii=False)[:300]}")
        self._save(passport=pp)
        return {"userid": pp.get("userid"), "account": pp.get("account")}

    # ---------- SMS code login ----------

    def send_sms(self, phone):
        pk = self.call("5020:localhost", {"deviceinfo": self._device()[1]},
                       encrypt_type=4, key_type=1)
        if not isinstance(pk, dict) or not pk.get("pubkey"):
            raise RuntimeError(f"public key fetch failed: {pk}")
        self.state["pubkey"], self.state["rsa_version"] = pk["pubkey"], pk.get("version", "")
        self._save()
        return self.call("1000:localhost", {
            "phone": self._rsa_wrap(pk["pubkey"], phone), "rsaversion": pk["version"],
            "type": "verify_origin", "deviceinfo": self._device()[0],
            "mobfunc": "11", "mt_flag": "1"}, encrypt_type=4, key_type=1)

    def login_sms(self, phone, code):
        body = {"phone": self._rsa_wrap(self.state["pubkey"], phone),
                "passwd": self._rsa_wrap(self.state["pubkey"], code),
                "rsaVersion": self.state["rsa_version"],
                "deviceinfo": self._device()[0], "type": "phone_origin",
                "mobfunc": "11", "mt_flag": "1"}
        out = self.call("1000:localhost", body, encrypt_type=4, key_type=1)
        pp = (out or {}).get("passport") or {}
        if not pp.get("token"):
            raise RuntimeError(f"login failed: {json.dumps(out, ensure_ascii=False)[:300]}")
        self._save(passport=pp)
        return {"userid": pp.get("userid"), "account": pp.get("account")}

    # ---------- positions ----------

    def _require_login(self):
        if not self.state.get("passport", {}).get("token"):
            sys.exit("Not logged in. Run: ths_position.py login -u <username> -p <password>")

    def list_accounts(self):
        self._require_login()
        out = self.call("4000:/caishen_fund/manage/stock",
                        {"deviceinfo": self._device()[1]}) or {}
        if isinstance(out, dict) and out.get("error_code"):
            raise RuntimeError(f"account list failed: {out}")
        accs = []
        for a in out.get("auto") or []:
            qsid = str(a.get("qsid", ""))
            accs.append({"qsid": qsid, "zjzh": a.get("zjzh"), "qsmc": a.get("qsmc"),
                         "fundkey": a.get("fundkey"), "rzrq": qsid.endswith("RZRQ")})
        return accs

    def get_positions(self, qsid, zjzh, margin=False):
        self._require_login()
        out = self.call("4000:/caishen_fund/stock_position/v1/auto_position",
                        {"flag": "2" if margin else "1", "qsid": qsid, "zjzh": zjzh}) or []
        if isinstance(out, list) and out:
            ex = out[0].get("ex_data") or {}
            if str(out[0].get("error_code", "0")) != "0":
                raise RuntimeError(f"snapshot failed: {out[0].get('error_msg')}")
            return ex
        return {}

    @staticmethod
    def normalize_snapshot(snap):
        """Server snapshot -> stable English keys, numeric types."""
        import datetime

        def num(v):
            try:
                return float(v)
            except (TypeError, ValueError):
                return 0.0

        ts = snap.get("asset_last_sync")
        positions = []
        for p in snap.get("data") or []:
            positions.append({
                "code": p.get("zqdm"), "name": p.get("zqmc"),
                "quantity": int(num(p.get("ccsl"))),
                "available": int(num(p.get("kysl"))),
                "avg_cost": num(p.get("cbjg")), "last_price": num(p.get("sj")),
                "market_value": num(p.get("sz")), "weight": num(p.get("cw")),
                "pnl": num(p.get("yke")), "pnl_pct": num(p.get("ykbl")),
                "industry": p.get("hy_name") or "", "hold_days": int(num(p.get("hold_days"))),
            })
        return {
            "cash_balance": num(snap.get("zjye")),
            "market_value": num(snap.get("zsz")),
            "total_assets": num(snap.get("zzc")) or num(snap.get("zjye")) + num(snap.get("zsz")),
            "daily_pnl": num(snap.get("dryk")),
            "positions": positions,
            "last_sync": (datetime.datetime.fromtimestamp(
                int(ts) / 1000, datetime.timezone.utc).isoformat()) if ts else None,
        }


def format_accounts_table(rows):
    lines = ["{:6}  {:14}  {:<20}  {:<12}".format("QSID", "ACCOUNT", "BROKER", "MARGIN")]
    for a in rows:
        lines.append("{:<6}  {:14}  {:<20}  {:<12}".format(
            a["qsid"], str(a["zjzh"]), str(a["qsmc"]), "yes" if a["rzrq"] else "no"))
    return "\n".join(lines)


def format_positions_table(rows):
    """rows: normalized per-account dicts from CLI `positions`."""
    lines = []
    for r in rows:
        lines.append("{} (qsid={} account={})".format(r["broker"], r["qsid"], r["zjzh"]))
        lines.append("  cash {:>14,.2f}   market value {:>14,.2f}   daily pnl {:>12,.2f}".format(
            r["cash_balance"], r["market_value"], r["daily_pnl"]))
        if r["positions"]:
            lines.append("  {:<10} {:<16} {:>8} {:>10} {:>10} {:>14} {:>12} {:>8} {:>7}".format(
                "CODE", "NAME", "QTY", "COST", "PRICE", "VALUE", "PNL", "PNL%", "WEIGHT"))
            for p in r["positions"]:
                lines.append("  {:<10} {:<16} {:>8} {:>10.3f} {:>10.3f} {:>14,.2f} {:>12,.2f} {:>7.2%} {:>6.1%}".format(
                    str(p["code"]), str(p["name"])[:14], p["quantity"], p["avg_cost"],
                    p["last_price"], p["market_value"], p["pnl"], p["pnl_pct"] / 100,
                    p["weight"]))
        else:
            lines.append("  (no holdings)")
        lines.append("  last sync: {}".format(r["last_sync"]))
    return "\n".join(lines)


def selftest():
    key = "abcdef1234567890"
    c = ThsPositionClient.__new__(ThsPositionClient)  # no state file touched
    for s in ("{}", '{"a":"x"}'):
        assert c._aes_dec(key, c._aes_enc(key, s)) == s
    assert len(base64.b64decode(c._rsa_wrap(WRAP_PUB, "x" * 16))) == 128
    print("selftest OK: aes-roundtrip, rsa-wrap")


def _out(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=1))


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="ths-position",
                                 description="THS Investment Ledger position query (read-only, unofficial)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest").set_defaults(fn=lambda a: selftest())

    p = sub.add_parser("login", help="login with credentials")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)

    p = sub.add_parser("sms-send", help="(alternative) send SMS verification code")
    p.add_argument("--phone", required=True)

    p = sub.add_parser("sms-login", help="(alternative) login with SMS code")
    p.add_argument("--phone", required=True)
    p.add_argument("--code", required=True)

    p = sub.add_parser("accounts", help="list bound broker accounts")
    p.add_argument("--format", default="json", choices=["json", "text"])
    p = sub.add_parser("positions", help="position snapshots (all accounts by default)")
    p.add_argument("--qsid")
    p.add_argument("--zjzh")
    p.add_argument("--format", default="json", choices=["json", "text"],
                   help="json=agent-friendly, text=human-friendly")

    a = ap.parse_args()
    if a.cmd == "selftest":
        return a.fn(a)
    c = ThsPositionClient()
    try:
        if a.cmd == "login":
            _out(c.login_password(a.username, a.password))
        elif a.cmd == "sms-send":
            _out(c.send_sms(a.phone) or {"sent": True})
        elif a.cmd == "sms-login":
            _out(c.login_sms(a.phone, a.code))
        elif a.cmd == "accounts":
            rows = c.list_accounts()
            if a.format == "text":
                print(format_accounts_table(rows))
            else:
                _out(rows)
        elif a.cmd == "positions":
            accs = c.list_accounts()
            if a.qsid and a.zjzh:
                accs = [x for x in accs if x["qsid"] == a.qsid and x["zjzh"] == a.zjzh]
                if not accs:
                    sys.exit("account not found")
            rows = []
            for acc in accs:
                snap = c.get_positions(acc["qsid"], acc["zjzh"], margin=acc["rzrq"])
                norm = dict(c.normalize_snapshot(snap))
                norm.update({"qsid": acc["qsid"], "zjzh": acc["zjzh"],
                             "broker": acc["qsmc"], "margin": acc["rzrq"]})
                rows.append(norm)
            if a.format == "text":
                print(format_positions_table(rows))
            else:
                _out(rows)
    except RuntimeError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
