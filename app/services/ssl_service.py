import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def get_ssl_certificate_info(url: str) -> dict:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return {"ssl": "invalid hostname"}

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        issued_by = issuer.get("organizationName", "unknown")

        valid_from = cert.get("notBefore")
        valid_to = cert.get("notAfter")

        valid_from_dt = datetime.strptime(valid_from, "%b %d %H:%M:%S %Y %Z")
        valid_to_dt = datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z")

        now = datetime.utcnow()

        return {
            "issuer": issued_by,
            "valid_from": str(valid_from_dt),
            "valid_to": str(valid_to_dt),
            "days_remaining": (valid_to_dt - now).days,
            "certificate_age_days": (now - valid_from_dt).days,
            "self_signed": cert.get("issuer") == cert.get("subject")
        }

    except Exception as e:
        return {
            "issuer": "unknown",
            "valid_from": "unknown",
            "valid_to": "unknown",
            "days_remaining": None,
            "certificate_age_days": None,
            "self_signed": "unknown",
            "error": str(e)
        }
