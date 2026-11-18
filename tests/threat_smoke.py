"""Run after tests/smoke.py and tests/threat.php --integration in a disposable database."""
import http.cookiejar
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = os.environ["SENTINEL_TEST_URL"]
USER = os.environ["SENTINEL_TEST_USER"]
PASSWORD = Path(os.environ["SENTINEL_TEST_PASSWORD_FILE"]).read_text().strip()
COUNT = 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def client():
    return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def get(opener, path, status=200, data=None, extra=None):
    global COUNT
    req = urllib.request.Request(BASE + path, data=data, headers=extra or {})
    try:
        response = opener.open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read()
        assert response.status == status, (path, response.status, status, re.sub(rb"<[^>]+>", b" ", body)[-400:])
        COUNT += 1
        return body, response.headers


def token(page):
    return re.search(rb'name="_csrf" value="([0-9a-f]{64})"', page)[1].decode()


def enter(username):
    opener = client()
    page, _ = get(opener, "/login")
    fields = {"_csrf": token(page), "username": username, "password": PASSWORD}
    get(opener, "/login", 303, urllib.parse.urlencode(fields).encode())
    return opener


admin = enter(USER)
csrf = token(get(admin, "/threat/dashboard")[0])


def form(path, action, status=303, **fields):
    return get(admin, path, status, urllib.parse.urlencode({"_csrf": csrf, "action": action, **fields}).encode())


def upload(path, field, filename, body, **fields):
    boundary = "SentinelThreatTestBoundary"
    part = "".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n' for key, value in {"_csrf": csrf, **fields}.items())
    suffix = f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'
    return get(admin, path, 303, (part + suffix).encode() + body + f"\r\n--{boundary}--\r\n".encode(), {"Content-Type": f"multipart/form-data; boundary={boundary}"})


for page in ("dashboard", "scan", "urls", "domains", "ips", "hashes", "phishing", "malware", "vulnerabilities", "advisories",
             "brand", "indicators", "correlation", "feeds", "monitor", "alerts", "reports", "settings"):
    get(admin, "/threat/" + page)

form("/threat/brand", "domain", domain="meridian.example.test", title="TEST reference", active="1")
_, headers = form("/threat/brand", "scan", indicator="meridan.example.test")
result, _ = get(admin, headers["Location"])
assert b"Jarak edit: 1" in result
form("/threat/ips", "scan", 422, indicator="example.test")

form("/threat/indicators", "manual", indicator="https://test-indicator.example.test/path?secret=yes", category="malware", severity="high", confidence="80")
_, response = form("/threat/urls", "scan", indicator="https://test-indicator.example.test/path?secret=yes")
result, _ = get(admin, response["Location"])
assert b"hxxps://test-indicator[.]example[.]test/path" in result and b"secret=yes" not in result and b"Indikator persis" in result
assert b"SHA-256 bukti" in result
scan = re.search(r"id=(\d+)$", response["Location"])[1]
get(admin, "/threat/scan?id=9999999", 404)

package, headers = get(admin, "/threat/indicators?export=json")
assert json.loads(package)["format"] == "sentinel-ioc-v1" and headers["X-Sentinel-Excluded-Redacted"] == "1"
upload("/threat/indicators", "package", "test.json", package, action="import", format="json")
csv, _ = get(admin, "/threat/indicators?export=csv")
assert csv.startswith(b"value,category") and b"example[.]test" in csv

_, headers = form("/threat/advisories", "add", provider="kemkes", title="TEST Healthcare advisory", summary="TEST Summary",
                  healthcare="1", reference="https://csirt.kemkes.go.id/imbauan/test", cve="CVE-2099-12345")
advisory, _ = get(admin, headers["Location"])
assert b"TEST Healthcare advisory" in advisory
advisory_id = re.search(r"id=(\d+)$", headers["Location"])[1]
form("/threat/advisories", "bookmark", id=advisory_id)
form("/threat/advisories", "read", id=advisory_id)
rss = b"<rss><channel><item><title>TEST Imported</title><description>TEST Brief</description><link>https://csirt.kemkes.go.id/imbauan/test</link></item></channel></rss>"
upload("/threat/advisories", "advisory", "test.xml", rss, action="import", provider="kemkes", format="rss")

asset_payload = urllib.parse.urlencode({"_csrf": csrf, "code": "TEST-TI-ASSET", "title": "TEST TI Asset", "brand": "TEST Vendor", "model": "TEST Product"}).encode()
get(admin, "/m/institutional_assets", 303, asset_payload)
cve_list, _ = get(admin, "/threat/vulnerabilities?q=CVE-2099-12345")
cve_id = re.search(rb'/threat/vulnerabilities\?id=(\d+)', cve_list)[1].decode()
_, response = form("/threat/vulnerabilities", "match", id=cve_id)
candidate, _ = get(admin,response["Location"])
assert b"TEST-TI-ASSET" in candidate and b"potensial" in candidate

_, response = form("/threat/reports", "create", kind="url", scan_id=scan)
report_path = response["Location"]
pdf, headers = get(admin, report_path + "/pdf")
assert pdf.startswith(b"%PDF-") and headers["Content-Type"].startswith("application/pdf")
form("/threat/reports", "approve", 422, id=report_path.rsplit("/", 1)[1])

roles, _ = get(admin, "/m/users")
role = re.search(rb'name="grants\[\]" value="(\d+)"[^>]+> Auditor', roles)[1].decode()
get(admin, "/m/users", 303, urllib.parse.urlencode({"_csrf": csrf, "title": "TEST TI Auditor", "username": "ti-synthetic-auditor",
    "password": PASSWORD, "active": "1", "grants[]": role}).encode())
auditor = enter("ti-synthetic-auditor")
get(auditor, "/threat/monitor")
get(auditor, "/threat/scan", 403)
get(auditor, report_path + "/pdf", 403)

get(admin, "/m/api_clients", 303, urllib.parse.urlencode({"_csrf": csrf, "title": "TEST TI Client", "active": "1",
    "scopes": "threat.dashboard.view,threat.scan.execute,threat.indicator.view"}).encode())
page, _ = get(admin, "/m/api_clients")
client_id, secret = re.search(rb'ID klien (\d+).*?<code>([a-f0-9]{64})</code>', page, re.S).groups()
api = client()
prefix = "/api/v1/threat-intelligence/"
get(api, prefix + "health", 401)
response, _ = get(api,"/api/v1/auth/token",data=json.dumps({"client_id": client_id.decode(), "client_secret": secret.decode()}).encode(),
                  extra={"Content-Type":"application/json"})
auth = {"Authorization": "Bearer " + json.loads(response)["access_token"], "Content-Type": "application/json"}
get(api,prefix + "health",extra=auth)
get(api,prefix + "summary",extra=auth)
items, _ = get(api,prefix + "indicators?state=active",extra=auth)
assert json.loads(items)["data"]["items"]
result, _ = get(api, prefix + "scan", 201, b'{"indicator":"test-indicator.example.test"}', auth)
assert json.loads(result)["data"]["matches"]
get(api,prefix + "scan",422,b'{"indicator":"http://user:secret@example.test"}',auth)
get(api,prefix + "providers",403,extra=auth)
get(api,prefix + "sync",403,b'{"provider":"cisa"}',auth)
print(f"{COUNT} Phase 2 HTTP checks passed.")
