from ipaddress import ip_address, ip_network
import json
import re
from urllib.parse import urlsplit

import httpx

from .database import InspectorError


PRIVATE_RANGES = tuple(
    ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
READ = re.compile(r"/(?:health|tasks(?:/[a-f0-9]{32})?|status)\Z")
WRITE = re.compile(
    r"/(?:analyze/(?:threat|vulnerability|malware|configuration|mitigation|education)|tasks/[a-f0-9]{32}/cancel)\Z"
)


class AiClient:
    def __init__(self, origin: str, token: str, mode: str):
        try:
            parts = urlsplit(origin.strip())
            ip = ip_address(parts.hostname)
            loopback = str(ip) in ("127.0.0.1", "::1")
            private = any(ip in network for network in PRIVATE_RANGES)
            if (
                not re.fullmatch(
                    r"https?://(?:\[[a-fA-F0-9:]+\]|[0-9.]+)(?::[1-9][0-9]{0,4})?/?", origin.strip()
                )
                or parts.port == 0
                or not (
                    (mode == "standalone" and loopback and parts.scheme in ("http", "https"))
                    or (mode == "central" and parts.scheme == "https" and (loopback or private))
                )
            ):
                raise ValueError
        except (ValueError, TypeError) as error:
            raise InspectorError(
                "Gunakan IP loopback untuk mode mandiri atau IP privat HTTPS untuk mode pusat."
            ) from error
        if not re.fullmatch(r"[a-f0-9]{64}", token.strip()):
            raise InspectorError("Token workstation AI yang valid diperlukan.")
        self.origin = origin.strip().rstrip("/")
        self.token = token.strip()
        self.loopback = loopback

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        if not ((method == "GET" and READ.fullmatch(path)) or (method == "POST" and WRITE.fullmatch(path))):
            raise InspectorError("Fungsi AI tidak tersedia.")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        try:
            with httpx.Client(timeout=8, follow_redirects=False, trust_env=not self.loopback) as client:
                with client.stream(
                    method, self.origin + "/api/v1/ai" + path, json=body, headers=headers
                ) as response:
                    if response.status_code == 401 or response.status_code == 403:
                        raise InspectorError("Workstation atau scope AI tidak diizinkan.")
                    if response.status_code >= 500:
                        raise InspectorError("AI Gateway tidak tersedia.")
                    if response.status_code >= 300:
                        raise InspectorError("Permintaan atau status tugas AI tidak valid.")
                    data = bytearray()
                    for chunk in response.iter_bytes(chunk_size=4096):
                        data.extend(chunk)
                        if len(data) > 1024 * 1024:
                            raise InspectorError("Respons AI melebihi batas.")
            payload = json.loads(data)
            if not isinstance(payload, dict):
                raise ValueError
            return payload
        except (httpx.HTTPError, ValueError) as error:
            raise InspectorError("Tidak dapat membaca respons AI Gateway.") from error
