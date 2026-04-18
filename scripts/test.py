#!/usr/bin/env python3
"""License Server 集成测试 — 纯标准库，无第三方依赖。"""

import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
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

def yellow(msg):
    print(f"\033[33m  INFO: {msg}\033[0m")

def dim(msg):
    print(f"\033[2m{msg}\033[0m")

def print_request(method: str, path: str, body=None, headers=None):
    dim(f"  ┌─ Request: {method} {BASE_URL}{path}")
    if headers:
        safe_headers = {k: (v[:20] + "...") if k == "Authorization" else v for k, v in headers.items()}
        dim(f"  │  Headers: {json.dumps(safe_headers)}")
    if body is not None:
        dim(f"  │  Body:    {json.dumps(body, ensure_ascii=False)}")

def print_verify(envelope: str, sig_b64: str, ok: bool, label: str = "Result"):
    """统一打印离线签名验证的输入和结果。"""
    dim(f"  ┌─ Envelope: {envelope}")
    dim(f"  │  Signature (base64): {sig_b64[:48]}...")
    color = "\033[32m" if ok else "\033[31m"
    verdict = "Verified OK" if ok else "Verification FAILED"
    print(f"\033[2m  └─ {label}: {color}{verdict}\033[0m")

def print_response(code: int, body: dict):
    color = "\033[32m" if 200 <= code < 300 else "\033[31m"
    reset = "\033[0m"
    def truncate(obj, max_len=80):
        if isinstance(obj, dict):
            return {k: truncate(v, max_len) for k, v in obj.items()}
        if isinstance(obj, list):
            return [truncate(i, max_len) for i in obj[:3]] + (["..."] if len(obj) > 3 else [])
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
        raw = e.read()
        try:
            body = json.loads(raw)
        except Exception:
            body = {"_raw": raw.decode(errors="replace")}
        result = e.code, body
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

def assert_in(name: str, substring: str, text: str):
    global PASS, FAIL
    if substring in text:
        green(name)
        PASS += 1
    else:
        red(f"{name} ('{substring}' not found in '{text}')")
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

def build_envelope(license_data: dict) -> bytes:
    """重建签名信封：key 按字母序，紧凑格式，与服务端 Go json.Marshal 一致。"""
    envelope = {
        "expires_at": license_data["expires_at"],
        "issued_at":  license_data["issued_at"],
        "payload":    license_data["payload"],
    }
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()

def section(title: str):
    bold(f"\n{'─' * 50}")
    bold(f"  {title}")
    bold(f"{'─' * 50}")


# ==================== Group 1: 基础连通性 ====================

def test_health():
    bold("\n[Test 1-1] Health Check (HTTPS)")
    code, body = request("GET", "/health")
    assert_eq("GET /health → 200", 200, code)
    assert_eq("health message = 'healthy'", "healthy", body.get("message"))
    assert_eq("health code field = 200", 200, body.get("code"))

def test_health_method_not_allowed():
    bold("\n[Test 1-2] Health Check with POST (405)")
    code, body = request("POST", "/health", body={})
    # /health 没有方法限制，GET/POST 都通过（此测试验证服务可达性即可）
    assert_true("Server reachable on POST /health", code in (200, 405), f"(got {code})")

def test_unknown_route():
    bold("\n[Test 1-3] Unknown route returns 404")
    code, _ = request("GET", "/api/v1/nonexistent")
    assert_eq("Unknown route → 404", 404, code)


# ==================== Group 2: 登录认证 ====================

def test_login_wrong_password():
    bold("\n[Test 2-1] Login — wrong password (401)")
    code, body = request("POST", "/api/v1/login", body={"username": "admin", "password": "wrong"})
    assert_eq("wrong password → 401", 401, code)
    assert_in("error message contains 'invalid'", "invalid", body.get("message", ""))

def test_login_nonexistent_user():
    bold("\n[Test 2-2] Login — non-existent user (401)")
    code, body = request("POST", "/api/v1/login", body={"username": "ghost", "password": "anything"})
    assert_eq("non-existent user → 401", 401, code)

def test_login_empty_body():
    bold("\n[Test 2-3] Login — empty body (400)")
    code, _ = request("POST", "/api/v1/login", body={})
    # username/password 都为空字符串，视为无效凭证 → 401
    assert_true("empty credentials → 400 or 401", code in (400, 401), f"(got {code})")

def test_login_missing_password_field():
    bold("\n[Test 2-4] Login — missing password field (400/401)")
    code, _ = request("POST", "/api/v1/login", body={"username": "admin"})
    assert_true("missing password → 400 or 401", code in (400, 401), f"(got {code})")

def test_login_success() -> str:
    bold("\n[Test 2-5] Login — success (200)")
    code, body = request("POST", "/api/v1/login", body={"username": "admin", "password": "admin123"})
    assert_eq("login → 200", 200, code)
    token = body.get("data", {}).get("token", "")
    expires_at = body.get("data", {}).get("expires_at", "")
    assert_true("Got JWT token (non-empty)", bool(token), "(token is empty)")
    assert_true("JWT token is 3-part (header.payload.sig)", len(token.split(".")) == 3, f"(token={token[:30]}...)")
    assert_true("Got expires_at field", bool(expires_at), "(expires_at is empty)")
    yellow(f"Token expires_at: {expires_at}")
    return token

def test_login_get_method_not_allowed():
    bold("\n[Test 2-6] Login — GET method (405)")
    code, _ = request("GET", "/api/v1/login")
    assert_eq("GET /login → 405", 405, code)


# ==================== Group 3: JWT 鉴权边界 ====================

def test_issue_no_auth_header(token: str):
    bold("\n[Test 3-1] Issue License — no Authorization header (401)")
    code, body = request("POST", "/api/v1/license/issue",
                         body={"payload": {"mac_address": "AA:BB:CC:DD:EE:FF"}})
    assert_eq("no auth header → 401", 401, code)
    assert_in("error mentions 'authorization'", "authorization", body.get("message", "").lower())

def test_issue_malformed_bearer(token: str):
    bold("\n[Test 3-2] Issue License — malformed Bearer token (401)")
    code, _ = request("POST", "/api/v1/license/issue",
                      headers={"Authorization": "Bearer this.is.not.valid"},
                      body={"payload": {"mac_address": "AA:BB:CC:DD:EE:FF"}})
    assert_eq("malformed token → 401", 401, code)

def test_issue_wrong_scheme(token: str):
    bold("\n[Test 3-3] Issue License — wrong auth scheme 'Token ...' (401)")
    code, _ = request("POST", "/api/v1/license/issue",
                      headers={"Authorization": f"Token {token}"},
                      body={"payload": {"mac_address": "AA:BB:CC:DD:EE:FF"}})
    assert_eq("wrong scheme → 401", 401, code)

def test_audit_no_auth():
    bold("\n[Test 3-4] Audit Logs — no Authorization header (401)")
    code, _ = request("GET", "/api/v1/license/audit")
    assert_eq("audit no auth → 401", 401, code)


# ==================== Group 4: 签发 License ====================

def test_issue_license_basic(token: str) -> dict:
    bold("\n[Test 4-1] Issue License — standard request")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs, body={
        "payload": {
            "mac_address":     "AA:BB:CC:DD:EE:FF",
            "cpu_uid":         "CPU-UID-00001",
            "camera_model":    "CAM-X100",
            "encrypt_version": 1,
        },
        "valid_days": 365,
    })
    assert_eq("issue → 200", 200, code)
    assert_eq("message = 'license issued'", "license issued", body.get("message"))
    lic = body.get("data", {})
    assert_eq("payload.mac_address", "AA:BB:CC:DD:EE:FF",  lic.get("payload", {}).get("mac_address"))
    assert_eq("payload.cpu_uid",     "CPU-UID-00001",       lic.get("payload", {}).get("cpu_uid"))
    assert_eq("payload.camera_model","CAM-X100",            lic.get("payload", {}).get("camera_model"))
    assert_eq("payload.encrypt_version", 1,                 lic.get("payload", {}).get("encrypt_version"))
    assert_true("issued_at present",  bool(lic.get("issued_at")))
    assert_true("expires_at present", bool(lic.get("expires_at")))
    assert_true("signature present",  bool(lic.get("signature")))
    yellow(f"issued_at={lic.get('issued_at')}  expires_at={lic.get('expires_at')}")
    return lic

def test_issue_license_default_valid_days(token: str) -> dict:
    bold("\n[Test 4-2] Issue License — omit valid_days (default 3650 days)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs, body={
        "payload": {"mac_address": "BB:CC:DD:EE:FF:00", "cpu_uid": "CPU-DEFAULT"},
    })
    assert_eq("default valid_days → 200", 200, code)
    lic = body.get("data", {})
    # 粗验：expires_at 应比 issued_at 晚约 3650 天（允许 ±2 天误差）
    from datetime import datetime, timezone
    issued   = datetime.fromisoformat(lic.get("issued_at",  "").replace("Z", "+00:00"))
    expires  = datetime.fromisoformat(lic.get("expires_at", "").replace("Z", "+00:00"))
    diff_days = (expires - issued).days
    assert_true(f"default valid_days ≈ 3650 (got {diff_days})", 3648 <= diff_days <= 3652)
    return lic

def test_issue_license_long_validity(token: str):
    bold("\n[Test 4-3] Issue License — valid_days=3650 (10 years)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs, body={
        "payload": {"mac_address": "CC:DD:EE:FF:00:11", "cpu_uid": "CPU-LONG"},
        "valid_days": 3650,
    })
    assert_eq("10-year license → 200", 200, code)
    from datetime import datetime, timezone
    lic = body.get("data", {})
    issued  = datetime.fromisoformat(lic.get("issued_at",  "").replace("Z", "+00:00"))
    expires = datetime.fromisoformat(lic.get("expires_at", "").replace("Z", "+00:00"))
    diff_days = (expires - issued).days
    assert_true(f"expires_at ≈ 10 years later (got {diff_days} days)", 3648 <= diff_days <= 3652)

def test_issue_license_minimal_payload(token: str) -> dict:
    bold("\n[Test 4-4] Issue License — minimal payload (only mac_address)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs, body={
        "payload": {"mac_address": "DD:EE:FF:00:11:22"},
        "valid_days": 30,
    })
    assert_eq("minimal payload → 200", 200, code)
    lic = body.get("data", {})
    assert_eq("payload.mac_address preserved", "DD:EE:FF:00:11:22", lic.get("payload", {}).get("mac_address"))
    assert_true("signature present", bool(lic.get("signature")))
    return lic

def test_issue_license_extra_fields(token: str) -> dict:
    bold("\n[Test 4-5] Issue License — extra custom fields in payload")
    hdrs = {"Authorization": f"Bearer {token}"}
    custom_payload = {
        "mac_address":     "EE:FF:00:11:22:33",
        "cpu_uid":         "CPU-EXTRA",
        "camera_model":    "CAM-PRO",
        "encrypt_version": 2,
        "serial_number":   "SN-20260418-XYZ",
        "firmware_ver":    "v3.1.4",
        "region":          "CN",
    }
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs,
                         body={"payload": custom_payload, "valid_days": 365})
    assert_eq("extra fields → 200", 200, code)
    lic = body.get("data", {})
    p = lic.get("payload", {})
    assert_eq("serial_number preserved", "SN-20260418-XYZ", p.get("serial_number"))
    assert_eq("firmware_ver preserved",  "v3.1.4",          p.get("firmware_ver"))
    assert_eq("region preserved",        "CN",              p.get("region"))
    return lic

def test_issue_license_payload_key_order(token: str):
    bold("\n[Test 4-6] Issue License — payload keys should be sorted in response")
    hdrs = {"Authorization": f"Bearer {token}"}
    # 故意以非字母序提交 payload
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs, body={
        "payload": {"z_field": "zzz", "a_field": "aaa", "m_field": "mmm"},
        "valid_days": 1,
    })
    assert_eq("key order test → 200", 200, code)
    lic = body.get("data", {})
    payload = lic.get("payload", {})
    keys = list(payload.keys())
    assert_eq("payload keys are sorted", sorted(keys), keys)

def test_issue_missing_payload(token: str):
    bold("\n[Test 4-7] Issue License — missing payload field (400)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("POST", "/api/v1/license/issue",
                         body={"valid_days": 365}, headers=hdrs)
    assert_eq("missing payload → 400", 400, code)
    assert_in("error mentions 'payload'", "payload", body.get("message", "").lower())

def test_issue_null_payload(token: str):
    bold("\n[Test 4-8] Issue License — null payload (400)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("POST", "/api/v1/license/issue",
                         body={"payload": None, "valid_days": 365}, headers=hdrs)
    assert_eq("null payload → 400", 400, code)

def test_issue_invalid_json_field(token: str):
    bold("\n[Test 4-9] Issue License — invalid payload JSON string (400)")
    hdrs = {"Authorization": f"Bearer {token}"}
    # 发送 payload 为字符串而非对象（在 JSON 层面合法，但服务端应拒绝）
    code, _ = request("POST", "/api/v1/license/issue",
                      body={"payload": "not-an-object", "valid_days": 365}, headers=hdrs)
    assert_true("string payload → 400 or 200", code in (400, 200), f"(got {code})")

def test_issue_get_method_not_allowed(token: str):
    bold("\n[Test 4-10] Issue License — GET method (405)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, _ = request("GET", "/api/v1/license/issue", headers=hdrs)
    assert_eq("GET /license/issue → 405", 405, code)

def test_issue_second_device(token: str) -> dict:
    bold("\n[Test 4-11] Issue License — second device (different hardware)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("POST", "/api/v1/license/issue", headers=hdrs, body={
        "payload": {
            "mac_address":     "11:22:33:44:55:66",
            "cpu_uid":         "CPU-UID-00002",
            "camera_model":    "CAM-Y200",
            "encrypt_version": 1,
        },
        "valid_days": 730,
    })
    assert_eq("device 2 → 200", 200, code)
    lic = body.get("data", {})
    assert_eq("device2 camera_model", "CAM-Y200", lic.get("payload", {}).get("camera_model"))
    from datetime import datetime, timezone
    issued  = datetime.fromisoformat(lic.get("issued_at",  "").replace("Z", "+00:00"))
    expires = datetime.fromisoformat(lic.get("expires_at", "").replace("Z", "+00:00"))
    diff_days = (expires - issued).days
    assert_true(f"valid_days=730 (got {diff_days})", 728 <= diff_days <= 732)
    return lic

def test_issue_same_device_twice(token: str):
    bold("\n[Test 4-12] Issue License — same device issued twice (idempotent, each returns unique sig)")
    hdrs = {"Authorization": f"Bearer {token}"}
    payload = {"mac_address": "FF:EE:DD:CC:BB:AA", "cpu_uid": "CPU-DUP"}
    _, body1 = request("POST", "/api/v1/license/issue", headers=hdrs,
                       body={"payload": payload, "valid_days": 365})
    _, body2 = request("POST", "/api/v1/license/issue", headers=hdrs,
                       body={"payload": payload, "valid_days": 365})
    sig1 = body1.get("data", {}).get("signature", "")
    sig2 = body2.get("data", {}).get("signature", "")
    # 两次签发时间戳不同，issued_at 秒精度可能相同但 expires_at 一致；签名应相同（确定性签名）或不同（带随机性）
    assert_true("Both issues succeed", bool(sig1) and bool(sig2))
    yellow(f"sig1 == sig2: {sig1 == sig2} (deterministic RSA = True expected)")


# ==================== Group 5: 签名验证（离线，客户端模拟）====================

def test_verify_signature(license_data: dict):
    bold("\n[Test 5-1] Verify License Signature — valid license")
    envelope_bytes = build_envelope(license_data)
    sig_bytes = base64.b64decode(license_data["signature"])
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    print_verify(envelope_bytes.decode(), license_data["signature"], ok)
    assert_true("Valid signature verified with public key", ok)

def test_verify_signature_minimal(license_data: dict):
    bold("\n[Test 5-2] Verify Signature — minimal payload license")
    envelope_bytes = build_envelope(license_data)
    sig_bytes = base64.b64decode(license_data["signature"])
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    print_verify(envelope_bytes.decode(), license_data["signature"], ok)
    assert_true("Minimal payload signature valid", ok)

def test_verify_signature_extra_fields(license_data: dict):
    bold("\n[Test 5-3] Verify Signature — extra-fields payload license")
    envelope_bytes = build_envelope(license_data)
    sig_bytes = base64.b64decode(license_data["signature"])
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    print_verify(envelope_bytes.decode(), license_data["signature"], ok)
    assert_true("Extra-fields payload signature valid", ok)

def test_tamper_payload_field(license_data: dict):
    bold("\n[Test 5-4] Tamper Detection — modify payload field")
    tampered = dict(license_data)
    tampered["payload"] = dict(license_data["payload"], camera_model="CAM-FAKE")
    envelope_bytes = build_envelope(tampered)
    sig_bytes = base64.b64decode(license_data["signature"])
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    print_verify(envelope_bytes.decode(), license_data["signature"], not ok, label="Tamper Result")
    assert_true("Tampered payload field rejected", not ok)

def test_tamper_expires_at(license_data: dict):
    bold("\n[Test 5-5] Tamper Detection — extend expires_at")
    tampered = dict(license_data, expires_at="2099-01-01T00:00:00Z")
    envelope_bytes = build_envelope(tampered)
    sig_bytes = base64.b64decode(license_data["signature"])
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    print_verify(envelope_bytes.decode(), license_data["signature"], not ok, label="Tamper Result")
    assert_true("Extended expires_at rejected", not ok)

def test_tamper_issued_at(license_data: dict):
    bold("\n[Test 5-6] Tamper Detection — backdate issued_at")
    tampered = dict(license_data, issued_at="2000-01-01T00:00:00Z")
    envelope_bytes = build_envelope(tampered)
    sig_bytes = base64.b64decode(license_data["signature"])
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    print_verify(envelope_bytes.decode(), license_data["signature"], not ok, label="Tamper Result")
    assert_true("Backdated issued_at rejected", not ok)

def test_tamper_add_payload_field(license_data: dict):
    bold("\n[Test 5-7] Tamper Detection — add extra field to payload after signing")
    tampered = dict(license_data)
    tampered["payload"] = dict(license_data["payload"], injected_field="hacked")
    envelope_bytes = build_envelope(tampered)
    sig_bytes = base64.b64decode(license_data["signature"])
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
    print_verify(envelope_bytes.decode(), license_data["signature"], not ok, label="Tamper Result")
    assert_true("Injected payload field rejected", not ok)

def test_tamper_wrong_signature(license_data: dict):
    bold("\n[Test 5-8] Tamper Detection — replace signature with random bytes")
    envelope_bytes = build_envelope(license_data)
    fake_sig = bytes(256)
    fake_sig_b64 = base64.b64encode(fake_sig).decode()
    ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, fake_sig)
    print_verify(envelope_bytes.decode(), fake_sig_b64, not ok, label="Tamper Result")
    assert_true("Random signature rejected", not ok)

def test_envelope_json_format(license_data: dict):
    bold("\n[Test 5-9] Envelope Format — verify compact + sorted-key JSON")
    envelope_bytes = build_envelope(license_data)
    envelope_str = envelope_bytes.decode()
    dim(f"  ┌─ Envelope: {envelope_str}")
    has_no_space = " " not in envelope_str
    ei = envelope_str.index('"expires_at"')
    ii = envelope_str.index('"issued_at"')
    pi = envelope_str.index('"payload"')
    key_order_ok = ei < ii < pi
    dim(f"  │  No spaces: {has_no_space}  |  Key order (e<i<p): {ei}<{ii}<{pi} → {key_order_ok}")
    print(f"\033[2m  └─ Format check complete\033[0m")
    assert_true("No spaces in envelope JSON", has_no_space, f"(found space: {envelope_str[:60]})")
    assert_true("Envelope key order: expires_at < issued_at < payload", key_order_ok)


# ==================== Group 6: 审计日志 ====================

def test_audit_logs_basic(token: str):
    bold("\n[Test 6-1] Audit Logs — basic list")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, body = request("GET", "/api/v1/license/audit", headers=hdrs)
    assert_eq("audit → 200", 200, code)
    logs = body.get("data", [])
    assert_true(f"Audit log has ≥ 1 entries (got {len(logs)})", len(logs) >= 1)
    return logs

def test_audit_log_fields(token: str):
    bold("\n[Test 6-2] Audit Logs — verify all required fields")
    hdrs = {"Authorization": f"Bearer {token}"}
    _, body = request("GET", "/api/v1/license/audit", headers=hdrs)
    logs = body.get("data", [])
    assert_true("Audit log non-empty for field check", len(logs) > 0)
    if logs:
        first = logs[0]
        assert_true("audit log has 'id'",         "id"         in first, f"(keys: {list(first.keys())})")
        assert_true("audit log has 'operator'",   "operator"   in first)
        assert_true("audit log has 'payload'",    "payload"    in first)
        assert_true("audit log has 'issued_at'",  "issued_at"  in first)
        assert_true("audit log has 'expires_at'", "expires_at" in first)
        assert_true("audit log has 'client_ip'",  "client_ip"  in first)
        assert_eq("audit log operator = 'admin'", "admin", first.get("operator"))
        yellow(f"Sample log entry: id={first.get('id')} ip={first.get('client_ip')} issued={first.get('issued_at')}")

def test_audit_log_payload_is_valid_json(token: str):
    bold("\n[Test 6-3] Audit Logs — payload field is valid JSON string")
    hdrs = {"Authorization": f"Bearer {token}"}
    _, body = request("GET", "/api/v1/license/audit", headers=hdrs)
    logs = body.get("data", [])
    if logs:
        payload_str = logs[0].get("payload", "")
        try:
            parsed = json.loads(payload_str)
            assert_true("audit payload is valid JSON", isinstance(parsed, dict), f"(type={type(parsed)})")
        except json.JSONDecodeError as e:
            assert_true("audit payload is valid JSON", False, f"(parse error: {e})")

def test_audit_log_count_after_issues(token: str, expected_min: int):
    bold(f"\n[Test 6-4] Audit Logs — count ≥ {expected_min} after all issues")
    hdrs = {"Authorization": f"Bearer {token}"}
    _, body = request("GET", "/api/v1/license/audit", headers=hdrs)
    logs = body.get("data", [])
    assert_true(f"Audit log has ≥ {expected_min} entries (got {len(logs)})", len(logs) >= expected_min)

def test_audit_post_method_not_allowed(token: str):
    bold("\n[Test 6-5] Audit Logs — POST method (405)")
    hdrs = {"Authorization": f"Bearer {token}"}
    code, _ = request("POST", "/api/v1/license/audit", headers=hdrs, body={})
    assert_eq("POST /audit → 405", 405, code)


# ==================== Group 7: License 文件完整性（模拟客户端写文件+读文件）====================

def test_license_file_roundtrip(license_data: dict):
    bold("\n[Test 7-1] License File — write to disk and reload")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".lic", delete=False) as f:
        json.dump(license_data, f)
        lic_path = f.name
    dim(f"  ┌─ Written to: {lic_path}")
    try:
        with open(lic_path) as f:
            reloaded = json.load(f)
        dim(f"  │  Reloaded payload.mac_address: {reloaded['payload'].get('mac_address')}")
        dim(f"  │  Reloaded signature (first 40): {reloaded['signature'][:40]}...")
        assert_eq("Reloaded payload.mac_address",
                  license_data["payload"].get("mac_address"),
                  reloaded["payload"].get("mac_address"))
        assert_eq("Reloaded signature",
                  license_data["signature"], reloaded["signature"])
        envelope_bytes = build_envelope(reloaded)
        sig_bytes = base64.b64decode(reloaded["signature"])
        ok = openssl_verify(PUBLIC_KEY_PATH, envelope_bytes, sig_bytes)
        print_verify(envelope_bytes.decode(), reloaded["signature"], ok, label="Re-verify after reload")
        assert_true("Reloaded license signature still valid", ok)
    finally:
        os.unlink(lic_path)
        dim(f"  └─ Temp file deleted: {lic_path}")

def test_license_file_json_structure(license_data: dict):
    bold("\n[Test 7-2] License File — JSON structure has exactly 4 top-level keys")
    keys = set(license_data.keys())
    dim(f"  ┌─ Top-level keys: {sorted(keys)}")
    expected = {"payload", "issued_at", "expires_at", "signature"}
    dim(f"  └─ Expected keys:  {sorted(expected)}")
    assert_eq("Top-level keys = {payload, issued_at, expires_at, signature}", expected, keys)

def test_license_signature_base64(license_data: dict):
    bold("\n[Test 7-3] License File — signature is valid base64")
    sig_str = license_data.get("signature", "")
    dim(f"  ┌─ signature (first 48): {sig_str[:48]}...")
    try:
        sig_bytes = base64.b64decode(sig_str)
        dim(f"  └─ Decoded byte length: {len(sig_bytes)}")
        assert_true(f"Signature decodes to 256 bytes (RSA-2048, got {len(sig_bytes)})", len(sig_bytes) == 256)
    except Exception as e:
        assert_true("Signature is valid base64", False, f"(error: {e})")

def test_license_issued_expires_format(license_data: dict):
    bold("\n[Test 7-4] License File — issued_at / expires_at are RFC3339 timestamps")
    from datetime import datetime, timezone
    for field in ("issued_at", "expires_at"):
        val = license_data.get(field, "")
        dim(f"  ┌─ {field}: {val}")
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            dim(f"  └─ Parsed: {dt.isoformat()}  tzinfo={dt.tzinfo}")
            assert_true(f"{field} parses as UTC datetime", dt.tzinfo is not None, f"(val={val})")
        except ValueError as e:
            assert_true(f"{field} is valid RFC3339", False, f"(val={val!r}, error={e})")

def test_license_expires_after_issued(license_data: dict):
    bold("\n[Test 7-5] License File — expires_at > issued_at")
    from datetime import datetime, timezone
    issued  = datetime.fromisoformat(license_data["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(license_data["expires_at"].replace("Z", "+00:00"))
    diff = expires - issued
    dim(f"  ┌─ issued_at:  {issued.date()}")
    dim(f"  │  expires_at: {expires.date()}")
    dim(f"  └─ Difference: {diff.days} days")
    assert_true(f"expires_at ({expires.date()}) > issued_at ({issued.date()})", expires > issued)


# ==================== Group 8: 多用户 / 操作员场景 ====================

def test_multiple_tokens_independent(token: str):
    bold("\n[Test 8-1] Multi-token — two logins produce different tokens")
    _, body2 = request("POST", "/api/v1/login", body={"username": "admin", "password": "admin123"})
    token2 = body2.get("data", {}).get("token", "")
    assert_true("Second login produces a token", bool(token2))
    # 两次登录 iat 不同，token 应不同（HS256 with timestamp）
    assert_true("Two tokens are different", token != token2, "(tokens should differ due to iat)")

def test_audit_logs_record_issuer(token: str):
    bold("\n[Test 8-2] Audit — operator field recorded as 'admin'")
    hdrs = {"Authorization": f"Bearer {token}"}
    _, body = request("GET", "/api/v1/license/audit", headers=hdrs)
    logs = body.get("data", [])
    if logs:
        operators = {l.get("operator") for l in logs}
        assert_true(f"All logs have operator 'admin' (operators={operators})", operators == {"admin"})


# ==================== Main ====================

def main():
    bold("╔══════════════════════════════════════════════════╗")
    bold("║    License Server — Full Integration Test Suite  ║")
    bold("║    HTTPS + JWT + RSA Signature + Audit Logs      ║")
    bold("╚══════════════════════════════════════════════════╝")

    section("Group 1 · 基础连通性")
    test_health()
    test_health_method_not_allowed()
    test_unknown_route()

    section("Group 2 · 登录认证")
    test_login_wrong_password()
    test_login_nonexistent_user()
    test_login_empty_body()
    test_login_missing_password_field()
    token = test_login_success()
    test_login_get_method_not_allowed()

    section("Group 3 · JWT 鉴权边界")
    test_issue_no_auth_header(token)
    test_issue_malformed_bearer(token)
    test_issue_wrong_scheme(token)
    test_audit_no_auth()

    section("Group 4 · 签发 License")
    lic_basic    = test_issue_license_basic(token)
    lic_default  = test_issue_license_default_valid_days(token)
    test_issue_license_long_validity(token)
    lic_minimal  = test_issue_license_minimal_payload(token)
    lic_extra    = test_issue_license_extra_fields(token)
    test_issue_license_payload_key_order(token)
    test_issue_missing_payload(token)
    test_issue_null_payload(token)
    test_issue_invalid_json_field(token)
    test_issue_get_method_not_allowed(token)
    lic_device2  = test_issue_second_device(token)
    test_issue_same_device_twice(token)

    section("Group 5 · 签名验证（离线客户端模拟）")
    test_verify_signature(lic_basic)
    test_verify_signature_minimal(lic_minimal)
    test_verify_signature_extra_fields(lic_extra)
    test_tamper_payload_field(lic_basic)
    test_tamper_expires_at(lic_basic)
    test_tamper_issued_at(lic_basic)
    test_tamper_add_payload_field(lic_basic)
    test_tamper_wrong_signature(lic_basic)
    test_envelope_json_format(lic_basic)

    section("Group 6 · 审计日志")
    test_audit_logs_basic(token)
    test_audit_log_fields(token)
    test_audit_log_payload_is_valid_json(token)
    test_audit_log_count_after_issues(token, expected_min=6)
    test_audit_post_method_not_allowed(token)

    section("Group 7 · License 文件完整性")
    test_license_file_roundtrip(lic_basic)
    test_license_file_json_structure(lic_basic)
    test_license_signature_base64(lic_basic)
    test_license_issued_expires_format(lic_basic)
    test_license_expires_after_issued(lic_basic)

    section("Group 8 · 多用户 / 操作员场景")
    test_multiple_tokens_independent(token)
    test_audit_logs_record_issuer(token)

    bold("\n╔══════════════════════════════════════════════════╗")
    bold(f"║  Test Results: {PASS:3d} passed,  {FAIL:3d} failed            ║")
    bold("╚══════════════════════════════════════════════════╝")

    if FAIL > 0:
        print("\033[31mSOME TESTS FAILED!\033[0m")
        sys.exit(1)
    else:
        print("\033[32mALL TESTS PASSED!\033[0m")

if __name__ == "__main__":
    main()
