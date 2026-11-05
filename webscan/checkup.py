"""只读安全体检：证书、HTTP 升级与响应头。"""

from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

import httpx

from .config import SECURITY_HEADERS


def check_site(target: str) -> dict:
    parts = urlsplit(target)
    host = parts.hostname
    tls_port = parts.port if parts.scheme == "https" and parts.port else 443
    address = f"[{host}]" if ":" in host else host
    authority = address if tls_port == 443 else f"{address}:{tls_port}"
    https_url = f"https://{authority}/"
    result = {"target": target, "certificate": {}, "redirect": {}, "headers": []}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, tls_port), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=host) as secure:
                cert = secure.getpeercert()
        expires = cert["notAfter"]
        result["certificate"] = {
            "valid": True,
            "expires": expires,
            "days": int((ssl.cert_time_to_seconds(expires) - time.time()) // 86400),
        }
    except (OSError, ValueError) as exc:
        result["certificate"] = {"valid": False, "error": str(exc)}

    with httpx.Client(timeout=5, trust_env=False) as client:
        http_port = parts.port if parts.scheme == "http" and parts.port else 80
        http_url = f"http://{address}:{http_port}/"
        try:
            with client.stream("GET", http_url) as response:
                location = response.headers.get("location", "")
                destination = urlsplit(urljoin(http_url, location))
                result["redirect"] = {
                    "enabled": response.is_redirect and destination.scheme == "https"
                    and destination.hostname == host and (destination.port or 443) == tls_port,
                    "status": response.status_code,
                    "location": location,
                }
        except (httpx.HTTPError, ValueError) as exc:
            result["redirect"] = {"error": str(exc)}

        try:
            with client.stream("GET", https_url) as response:
                result["https_status"] = response.status_code
                for name, description, _ in [("strict-transport-security", "强制后续访问使用 HTTPS", ""), *SECURITY_HEADERS]:
                    result["headers"].append({
                        "name": name, "description": description,
                        "value": response.headers.get(name, ""),
                    })
        except httpx.HTTPError as exc:
            result["https_error"] = str(exc)
    return result
