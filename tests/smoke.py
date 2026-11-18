"""Run against a disposable, migrated, empty database with one administrator account."""
import base64
import csv
import hashlib
import hmac
import http.cookiejar
import io
import json
import os
import re
import struct
import time
import zlib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = os.environ.get("SENTINEL_TEST_URL", "http://127.0.0.1:8080")
USERNAME = os.environ["SENTINEL_TEST_USER"]
PASSWORD = Path(os.environ["SENTINEL_TEST_PASSWORD_FILE"]).read_text().rstrip("\r\n")
COUNT = 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def browser():
    return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(client, path, status=200, fields=None, body=None, headers=None):
    global COUNT
    req = urllib.request.Request(BASE + path, data=body if fields is None else urllib.parse.urlencode(fields, doseq=True).encode(), headers=headers or {})
    try:
        response = client.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        received = response.read()
        assert response.code == status, (path, status, response.code, re.sub(rb"<[^>]+>", b" ", received)[-700:])
        COUNT += 1
        return received, response.headers


def csrf(body):
    match = re.search(rb'name="_csrf" value="([a-f0-9]{64})"', body)
    assert match, "No CSRF token on expected form"
    return match[1].decode()


def form_data(token, action, field, filename, content, mime):
    boundary = "SentinelSmokeBoundary"
    items = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="_csrf"\r\n\r\n{token}\r\n',
        f'--{boundary}\r\nContent-Disposition: form-data; name="action"\r\n\r\n{action}\r\n',
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\nContent-Type: {mime}\r\n\r\n',
    ]
    return "".join(items).encode() + content + f"\r\n--{boundary}--\r\n".encode(), {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def record_id(client, module, name):
    page = request(client, "/m/" + module + "?" + urllib.parse.urlencode({"q": name}))[0]
    assert name.encode() in page
    match = re.search(rb'href="/m/[^"]+\?id=(\d+)&amp;page=', page)
    assert match, "No result link for " + module
    return int(match[1])


admin = browser()
_, redirect_headers = request(admin, "/", 303)
login, headers = request(admin, "/login")
assert "Content-Security-Policy" in headers and "HttpOnly" in redirect_headers["Set-Cookie"]
request(admin, "/login", 403, fields={"username": USERNAME, "password": PASSWORD})
request(admin, "/login", 401, fields={"_csrf": csrf(login), "username": USERNAME, "password": "invalid"})
request(admin, "/login", 303, fields={"_csrf": csrf(login), "username": USERNAME, "password": PASSWORD})
dashboard, _ = request(admin, "/")
assert b"Basis data tersambung" in dashboard
token = csrf(dashboard)
for route in ["notifications", "activity_periods", "activities", "inspection_schedules", "education", "url_inspections", "file_inspections", "institutional_assets", "security_checklists", "security_findings", "security_incidents", "reports", "users", "roles", "audit_logs", "api_clients", "backup_history", "system_settings"]:
    request(admin, "/m/" + route)
for route in ["/system", "/statistics", "/analysis", "/archive", "/profile", "/assets/vendor/bootstrap.min.css", "/assets/vendor/chart.js"]:
    request(admin, route)


def save(module, status=303, **fields):
    return request(admin, "/m/" + module, status, fields={"_csrf": token, **fields})


save("activity_periods", title="SMOKE Period", starts_on="2026-11-01", ends_on="2026-11-30")
period = record_id(admin, "activity_periods", "SMOKE Period")
save("activities", title="SMOKE Activity", code="SMOKE-K", activity_year="2026", period_id=period,
     held_on="2026-11-15", state="dijadwalkan", participant_count=9)
activity = record_id(admin, "activities", "SMOKE Activity")
save("activities", id=activity, title="SMOKE Activity", code="SMOKE-K", activity_year="2026",
     period_id=period, held_on="2026-11-15", state="arsip", history_note="Documented for archive")
assert b"Documented for archive" in request(admin, f"/m/activities?id={activity}")[0]
assert b"SMOKE-K" in request(admin, "/m/activities?export=csv")[0]
save("inspection_schedules", title="SMOKE Schedule", activity_id=activity, scheduled_on="2026-11-15", state="selesai")
filtered, _ = request(admin, "/?month=2026-11")
assert b"2026-11-15" in filtered and b"data-chart=" in filtered

save("institutional_assets", title="SMOKE Asset", code="SMOKE-A", owner_unit="SMOKE Unit", history_note="Device updated")
asset = record_id(admin, "institutional_assets", "SMOKE Asset")
assert b"Device updated" in request(admin, f"/m/institutional_assets?id={asset}")[0]
export, _ = request(admin, "/m/institutional_assets?export=csv")
columns = next(csv.reader(io.StringIO(export.decode())))
output = io.StringIO(newline="")
writer = csv.DictWriter(output, fieldnames=columns)
writer.writeheader()
writer.writerow({"code": "SMOKE-CSV", "title": "SMOKE Imported Asset"})
payload, metadata = form_data(token, "import", "csv", "asset.csv", output.getvalue().encode(), "text/csv")
request(admin, "/m/institutional_assets", 303, body=payload, headers=metadata)
imported = record_id(admin, "institutional_assets", "SMOKE Imported Asset")
save("institutional_assets", action="hapus", id=imported)
request(admin, f"/m/institutional_assets?id={imported}", 404)

save("security_checklists", title="SMOKE Checklist", asset_id=asset, **{"check[1]": "memenuhi"})
check = record_id(admin, "security_checklists", "SMOKE Checklist")
assert b"Hasil checklist" in request(admin, f"/m/security_checklists?id={check}")[0]
save("url_inspections", title="https://example.org/smoke-verify?token=redacted")
url = record_id(admin, "url_inspections", "smoke-verify")
details, _ = request(admin, f"/m/url_inspections?id={url}")
assert b"token=redacted" not in details and b"istilah autentikasi" in details
save("url_inspections", 422, title="ftp://example.org/")

payload, metadata = form_data(token, "", "file", "sentinel-smoke.txt", b"inert smoke fixture", "text/plain")
request(admin, "/m/file_inspections", 303, body=payload, headers=metadata)
request(admin, "/m/file_inspections", 303, body=payload, headers=metadata)
file_id = record_id(admin, "file_inspections", "sentinel-smoke.txt")
file_page, _ = request(admin, f"/m/file_inspections?id={file_id}")
assert b"Belum diperiksa antivirus" in file_page and b"SHA-256" in file_page
request(admin, "/storage/uploads/example", 404)

save("security_findings", title="SMOKE Finding", asset_id=asset, category="configuration", severity="rendah", state="draf")
finding = record_id(admin, "security_findings", "SMOKE Finding")
save("security_findings", 422, id=finding, title="SMOKE Finding", state="selesai")
for state in ["verifikasi", "mitigasi", "pemeriksaan_ulang", "selesai"]:
    save("security_findings", id=finding, title="SMOKE Finding", asset_id=asset, state=state)
save("security_incidents", title="SMOKE Incident", category="lainnya", state="terbuka", history_note="Triage began")
incident = record_id(admin, "security_incidents", "SMOKE Incident")
assert b"Triage began" in request(admin, f"/m/security_incidents?id={incident}")[0]

def png_chunk(name, data):
    return struct.pack(">I", len(data)) + name + data + struct.pack(">I", zlib.crc32(name + data))


logo = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
logo += png_chunk(b"IDAT", zlib.compress(b"\x00\x20\x40\x80")) + png_chunk(b"IEND", b"")
payload, metadata = form_data(token, "", "logo", "logo.png", logo, "image/png")
request(admin, "/institution-logo", 303, body=payload, headers=metadata)
received_logo, logo_headers = request(admin, "/institution-logo")
assert received_logo.startswith(logo[:8]) and logo_headers["Content-Type"] == "image/png"

report_fields = {"title": "SMOKE Report", "code": "SMOKE-R", "source": "kegiatan",
                 "notes": "Report smoke", "inspected_on": "2026-11-15"}
save("reports", state="draf", **report_fields)
report = record_id(admin, "reports", "SMOKE Report")
for state in ["diajukan", "disetujui"]:
    save("reports", id=report, state=state, **report_fields)
preview, _ = request(admin, f"/reports/{report}")
assert b"Report smoke" in preview and b"SMOKE-K" in preview and b"data:image/png;base64," in preview
pdf, headers = request(admin, f"/reports/{report}/pdf")
assert pdf.startswith(b"%PDF-") and len(pdf) > 1000 and headers["Content-Type"].startswith("application/pdf")

save("api_clients", title="SMOKE Desktop", active=1, scopes="assets.read")
client_page, _ = request(admin, "/m/api_clients")
pair = re.search(rb'ID klien (\d+).*?<code>([a-f0-9]{64})</code>', client_page, flags=re.S)
assert pair
api = browser()
assert json.loads(request(api, "/api/v1/health")[0])["status"] == "ok"
request(api, "/api/v1/assets", 401)
api_payload = json.dumps({"client_id": int(pair[1]), "client_secret": pair[2].decode()}).encode()
api_result, _ = request(api, "/api/v1/auth/token", body=api_payload, headers={"Content-Type": "application/json"})
authorization = {"Authorization": "Bearer " + json.loads(api_result)["access_token"]}
items = json.loads(request(api, "/api/v1/assets", headers=authorization)[0])["data"]
assert any(item["code"] == "SMOKE-A" for item in items)
request(api, "/api/v1/reports", 403, headers=authorization)

request(admin, "/backup", 303, fields={"_csrf": token, "action": "create"})
backups, _ = request(admin, "/m/backup_history")
backup = int(re.search(rb'/m/backup_history\?id=(\d+)', backups)[1])
ciphertext, _ = request(admin, "/backup", fields={"_csrf": token, "action": "download", "id": backup})
assert len(ciphertext) > 100 and b"SMOKE Asset" not in ciphertext
save("institutional_assets", id=asset, title="SMOKE Changed Asset", code="SMOKE-A")
request(admin, "/backup", 422, fields={"_csrf": token, "action": "restore", "id": backup})
request(admin, "/backup", 303, fields={"_csrf": token, "action": "restore", "id": backup, "confirmation": "PULIHKAN"})
assert b"SMOKE Asset" in request(admin, f"/m/institutional_assets?id={asset}")[0]
assert b"restore" in request(admin, "/m/audit_logs?q=restore")[0]

users, _ = request(admin, "/m/users")
auditor_role = re.search(rb'name="grants\[\]" value="(\d+)"[^>]+> Auditor', users)
assert auditor_role, "Missing seeded Auditor role"
save("users", title="SMOKE Auditor", username="smoke-auditor", active=1, password=PASSWORD, **{"grants[]": auditor_role[1].decode()})
auditor = browser()
auditor_login = request(auditor, "/login")[0]
request(auditor, "/login", 303, fields={"_csrf": csrf(auditor_login), "username": "smoke-auditor", "password": PASSWORD})
request(auditor, "/m/audit_logs")
request(auditor, "/m/institutional_assets", 403)
request(auditor, f"/reports/{report}/pdf", 403)
def totp(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1_000_000:06d}"


profile = request(auditor, "/profile")[0]
request(auditor, "/profile", 303, fields={"_csrf": csrf(profile), "current": PASSWORD, "action": "totp-start"})
profile = request(auditor, "/profile")[0]
secret = re.search(rb'<code>([A-Z2-7]{32})</code>', profile)[1].decode()
step = int(time.time()) // 30
request(auditor, "/profile", 303, fields={"_csrf": csrf(profile), "current": PASSWORD,
        "action": "totp-confirm", "totp": totp(secret, step - 1)})
request(auditor, "/m/audit_logs", 303)
login = request(auditor, "/login")[0]
factor = totp(secret, step)
request(auditor, "/login", 401, fields={"_csrf": csrf(login), "username": "smoke-auditor", "password": PASSWORD})
request(auditor, "/login", 303, fields={"_csrf": csrf(login), "username": "smoke-auditor", "password": PASSWORD, "totp": factor})
auditor_page = request(auditor, "/m/audit_logs")[0]
request(auditor, "/logout", 303, fields={"_csrf": csrf(auditor_page)})
login = request(auditor, "/login")[0]
request(auditor, "/login", 401, fields={"_csrf": csrf(login), "username": "smoke-auditor", "password": PASSWORD, "totp": factor})

blocked = browser()
login = request(blocked, "/login")[0]
failed_login = {"_csrf": csrf(login), "username": "smoke-absent", "password": "incorrect"}
for attempt in range(9):
    request(blocked, "/login", 429 if attempt == 8 else 401, fields=failed_login)

request(admin, "/logout", 303, fields={"_csrf": token})
request(admin, "/m/users", 303)

print(f"{COUNT} HTTP requests met their expected result. Content assertions passed.")
