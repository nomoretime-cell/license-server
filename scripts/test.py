#!/usr/bin/env python3
"""License Server 集成测试 — 纯标准库，无第三方依赖。"""

import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error

BASE_URL = "https://127.0.0.1:8443"
PUBLIC_KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "keys", "public.pem")
TLS_CERT_PATH = os.path.join(os.path.dirname(__file__), "..", "certs", "server.crt")

PASS = 0
FAIL = 0

# Trust the self-signed certificate for testing
SSL_CTX = ssl.create_default_context()
SSL_CTX.load_verify_locations(TLS_CERT_PATH)


# ==================== Helpers ====================

def green(msg):
    print(f"\033[32m  PASS: {msg}\033[0m")

def red(msg):
    print(f"\033[31m  FAIL: {msg}\033[0m")

def bold(msg):
    print(f"\033[1m{msg}\033[0m")

def dim(msg):
    print(f"\033[2m{msg}\033[0m")

def print_request(method: str, path: str, body=None, headers=None):
    dim(f"  ┌─ Request: {method} {BASE_URL}{path}")
    if headers:
        safe_headers = {k: (v[:20] + "...") if k == "Authorization" else v for k, v in headers.items()}
        dim(f"  │  Headers: {json.dumps(safe_headers)}")
    if body:
        dim(f"  │  Body:    {json.dumps(body, ensure_ascii=False)}")

def print_response(code: int, body: dict):
    color = "\033[32m" if 200 <= code < 300 else "\033[31m"
    reset = "\033[0m"
    # 截断过长字段（如 signature、token）以免输出过于冗长
    def truncate(obj, max_len=60):
        if isinstance(obj, dict):
            return {k: truncate(v, max_len) for k, v in obj.items()}
        if isinstance(obj, str) and len(obj) > max_len:
            return obj[:max_len] + "..."
        return obj
    print(f"\033[2m  └─ Response: {color}{code}{reset}\033[2m  {json.dumps(truncate(body), ensure_ascii=False)}\033[0m")

def request(method: str, path: str, body=None, headers=None) -> tuple:
    """发送 HTTPS 请求，返回 (status_code, response_body_dict)，并打印输入输出。"""
    print_request(method, path, body, headers)
    url = BASE_URL + path
    data = json.dumps(body).encode() if body else None
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=SSL_CTX) as resp:
            result = resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        result = e.code, json.loads(e.read())
    except Exception as e:
        result = 0, {"error": str(e)}
    print_response(*result)
    return result

def assert_eq(name: str, expected, actual):
    global PASS, FAIL
    if expected == actual:
        green(name)
        PASS += 1
    else:
        red(f"{name} (expected {expected!r}, got {actual!r})")
        FAIL += 1

def assert_true(name: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        green(name)
        PASS += 1
    else:
        red(f"{name} {detail}")
        FAIL += 1

def openssl_verify(pub_key_path: str, data: bytes, signature: bytes) -> bool:
    """用 openssl 命令行验证 RSA-SHA256 签名。"""
    with tempfile.NamedTemporaryFile(delete=False) as f_data:
        f_data.write(data)
        data_path = f_data.name
    with tempfile.NamedTemporaryFile(delete=False) as f_sig:
        f_sig.write(signature)
        sig_path = f_sig.name
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pub_key_path, "-signature", sig_path, data_path],
            capture_output=True, text=True,
        )
        return "Verified OK" in result.stdout
    finally:
        os.unlink(data_path)
        os.unlink(sig_path)


# ==================== Tests ====================

def test_health():
    bold("\n[Test 1] Health Check (HTTPS)")
    code, body = request("GET", "/health")
    assert_eq("GET /health status", 200, code)
    assert_eq("health message", "healthy", body.get("message"))

def test_login_wrong_password():
    bold("\n[Test 2] Login with wrong password (should fail 401)")
    code, _ = request("POST", "/api/v1/login", body={"username": "admin", "password": "wrong"})
    assert_eq("POST /login wrong password", 401, code)

def test_login_success() -> str:
    bold("\n[Test 3] Successful Login")
    code, body = request("POST", "/api/v1/login", body={"username": "admin", "password": "admin123"})
    assert_eq("POST /login status", 200, code)
    token = body.get("data", {}).get("token", "")
    assert_true("Got JWT token", bool(token), "(token is empty)")
    return token

def test_issue_no_jwt():
    bold("\n[Test 4] Issue License without JWT (should fail 401)")
    code, _ = request("POST", "/api/v1/license/issue",
                       body={"payload": {"mac_address": "AA:BB:CC:DD:EE:FF", "cpu_uid": "CPU123"}})
    assert_eq("POST /license/issue no JWT", 401, code)

def test_issue_license(token: str) -> dict:
    bold("\n[Test 5] Issue License (valid request)")
    hdrs = {"Authorization": f"Bearer {token}"}
    hw_payload = {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "cpu_uid": "CPU-UID-00001",
        "camera_model": "CAM-X100",
        "encrypt_version": 1,
    }
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs, body={
        "payload": hw_payload,
        "valid_days": 365,
    })
    assert_eq("POST /license/issue status", 200, code)
    assert_eq("license message", "license issued", body.get("message"))
    lic = body.get("data", {})
    assert_eq("payload mac", "AA:BB:CC:DD:EE:FF", lic.get("payload", {}).get("mac_address"))
    assert_eq("payload cpu", "CPU-UID-00001", lic.get("payload", {}).get("cpu_uid"))
    assert_eq("payload model", "CAM-X100", lic.get("payload", {}).get("camera_model"))
    assert_true("Has issued_at", bool(lic.get("issued_at")))
    assert_true("Has expires_at", bool(lic.get("expires_at")))
    assert_true("Got digital signature", bool(lic.get("signature")))
    return lic

def test_issue_second_device(token: str):
    bold("\n[Test 6] Issue License for second device")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs, body={
        "payload": {
            "mac_address": "11:22:33:44:55:66",
            "cpu_uid": "CPU-UID-00002",
            "camera_model": "CAM-Y200",
            "encrypt_version": 1,
        },
        "valid_days": 730,
    })
    assert_eq("POST /license/issue device 2 status", 200, code)
    assert_eq("payload model device2", "CAM-Y200", body.get("data", {}).get("payload", {}).get("camera_model"))

def test_audit_logs(token: str):
    bold("\n[Test 7] Get Audit Logs")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("GET", "/api/v1/license/audit", headers=hdrs)
    assert_eq("GET /license/audit status", 200, code)
    logs = body.get("data", [])
    assert_true(f"Audit log has {len(logs)} entries (>= 2)", len(logs) >= 2)
    assert_eq("audit log operator", "admin", logs[0].get("operator"))
    assert_true("audit log has payload", bool(logs[0].get("payload")))

def test_missing_payload(token: str):
    bold("\n[Test 8] Issue License with missing payload (should fail)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, _ = request("POST", "/api/v1/license/issue", body={"valid_days": 365}, headers=hdrs)
    assert_eq("POST /license/issue missing payload", 400, code)

def build_envelope(license_data: dict) -> bytes:
    """Reconstruct the signed envelope matching Go json.Marshal field order:
    expires_at, issued_at, payload (alphabetical by JSON tag)."""
    envelope = {
        "expires_at": license_data["expires_at"],
        "issued_at": license_data["issued_at"],
        "payload": license_data["payload"],
    }
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()

def test_verify_signature(license_data: dict):
    bold("\n[Test 9] Verify License Signature (client-side simulation)")
    envelope_bytes = build_envelope(license_data)
    sig_bytes = base64.b64decode(license_data["signature"])
    dim(f"  ┌─ Input:  envelope = {envelope_bytes.decode()}")
    dim(f"  │         signature (base64) = {license_data['signature'][:40]}...")
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    color = "\033[32m" if ok else "\033[31m"
    print(f"\033[2m  └─ Result: {color}{'Verified OK' if ok else 'Verification FAILED'}\033[0m")
    assert_true("Signature verified with public key", ok)

def test_tamper_detection(license_data: dict):
    bold("\n[Test 10] Tamper Detection (modify payload, signature should fail)")
    tampered = dict(license_data)
    tampered["payload"] = dict(license_data["payload"], camera_model="CAM-FAKE")
    envelope_bytes = build_envelope(tampered)
    sig_bytes = base64.b64decode(license_data["signature"])
    dim(f"  ┌─ Input:  tampered envelope = {envelope_bytes.decode()}")
    dim(f"  │         original signature (base64) = {license_data['signature'][:40]}...")
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    color = "\033[32m" if not ok else "\033[31m"
    print(f"\033[2m  └─ Result: {color}{'Correctly rejected (Verification FAILED)' if not ok else 'ERROR: tampered payload was accepted!'}\033[0m")
    assert_true("Tampered payload correctly rejected", not ok)


# ==================== Main ====================

def main():
    bold("============================================")
    bold("  License Server Integration Test Suite")
    bold("  (HTTPS + JWT Auth)")
    bold("============================================")

    test_health()
    test_login_wrong_password()
    token = test_login_success()
    test_issue_no_jwt()
    lic = test_issue_license(token)
    test_issue_second_device(token)
    test_audit_logs(token)
    test_missing_payload(token)
    test_verify_signature(lic)
    test_tamper_detection(lic)

    bold("\n============================================")
    bold(f"  Test Results: {PASS} passed, {FAIL} failed")
    bold("============================================")

    if FAIL > 0:
        print("\033[31mSOME TESTS FAILED!\033[0m")
        sys.exit(1)
    else:
        print("\033[32mALL TESTS PASSED!\033[0m")

if __name__ == "__main__":
    main()
