"""Integration check against a migrated PHP site and a running AI gateway."""
import http.cookiejar
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


base = os.environ["SENTINEL_TEST_URL"]
client = urllib.request.build_opener(NoRedirect(),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
http_checks = 0


def request(path,status=200,fields=None):
    global http_checks
    data = None if fields is None else urllib.parse.urlencode(fields).encode()
    try:
        response = client.open(urllib.request.Request(base+path,data=data),timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload=response.read()
        assert response.code==status,(path,response.code,status,re.sub(rb"<[^>]*>",b"",payload)[-400:])
        http_checks+=1
        return payload,response.headers


def csrf(html):
    return re.search(rb'name="_csrf" value="([0-9a-f]{64})"',html)[1].decode()


request("/ai/dashboard",303)
login,_=request("/login")
request("/login",303,{"_csrf":csrf(login),"username":os.environ["SENTINEL_TEST_USER"],
    "password":Path(os.environ["SENTINEL_TEST_PASSWORD_FILE"]).read_text().strip()})
dashboard,_=request("/ai/dashboard")
assert b"AI Dashboard" in dashboard and b"Ollama" in dashboard
token=csrf(dashboard)
for page in ("assistant","threat","malware","vulnerability","configuration","correlation","mitigation","report","executive",
             "knowledge","rag","models","tasks","evaluation","settings","audit"):
    request("/ai/"+page)
request("/ai/vulnerability?cve=CVE-2021-44228")
request("/ai/vulnerability",403,{"action":"enqueue","cve":"CVE-9999-999999999"})
request("/ai/vulnerability",422,{"_csrf":token,"action":"enqueue","cve":"TEST-INVALID"})
_,headers=request("/ai/vulnerability",303,{"_csrf":token,"action":"enqueue","cve":"CVE-9999-999999999"})
job=headers["Location"]
assert re.fullmatch(r"/ai/tasks/[0-9a-f]{32}",job)
for retry in range(15):
    state=json.loads(request(job+"/state")[0])["state"]
    if state not in ("pending","processing"):
        break
    time.sleep(.35)
assert state=="requires_review"
view,_=request(job)
assert b"Bukti belum cukup" in view
result=json.loads(request(job+"/json")[0])["result"]
assert result["status"]=="insufficient_evidence" and result["model_name"] is None
request(job+"/pdf",409)
request("/ai/tasks",409,{"_csrf":token,"action":"review","id":job.split("/")[-1],"decision":"verified"})
request("/api/v1/ai/health",401)
for path in ("/","/threat/dashboard","/m/institutional_assets"):
    request(path)
print(f"{http_checks} PHP–AI HTTP checks passed.")
