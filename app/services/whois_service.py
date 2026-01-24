import whois
from datetime import datetime
from urllib.parse import urlparse


def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def normalize_datetime(dt):
    """
    Converts timezone-aware datetime to naive UTC datetime
    """
    if dt and hasattr(dt, "tzinfo") and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


def get_whois_data(url: str) -> dict:
    try:
        domain = extract_domain(url)
        w = whois.whois(domain)

        creation_date = w.creation_date
        expiration_date = w.expiration_date

        # Handle list returns
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # Normalize timezone-aware datetimes
        if creation_date and creation_date.tzinfo:
            creation_date = creation_date.replace(tzinfo=None)
        if expiration_date and expiration_date.tzinfo:
            expiration_date = expiration_date.replace(tzinfo=None)

        domain_age_days = None
        if creation_date:
            domain_age_days = (datetime.utcnow() - creation_date).days

        return {
            "domain": domain,
            "creation_date": str(creation_date) if creation_date else "unknown",
            "expiration_date": str(expiration_date) if expiration_date else "unknown",
            "registrar": w.registrar or "unknown",
            "registrant_country": w.country or "unknown",
            "domain_age_days": domain_age_days,
            "privacy_protected": True if w.org is None else False
        }

    except Exception as e:
        return {
            "domain": domain if 'domain' in locals() else "unknown",
            "creation_date": "unknown",
            "expiration_date": "unknown",
            "registrar": "unknown",
            "registrant_country": "unknown",
            "domain_age_days": None,
            "privacy_protected": "unknown",
            "error": str(e)
        }

    try:
        domain = extract_domain(url)
        w = whois.whois(domain)

        creation_date = w.creation_date
        expiration_date = w.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        creation_date = normalize_datetime(creation_date)
        expiration_date = normalize_datetime(expiration_date)

        domain_age_days = None
        if creation_date:
            domain_age_days = (datetime.utcnow() - creation_date).days

        return {
            "domain": domain,
            "creation_date": str(creation_date) if creation_date else "unknown",
            "expiration_date": str(expiration_date) if expiration_date else "unknown",
            "registrar": w.registrar or "unknown",
            "registrant_country": w.country or "unknown",
            "domain_age_days": domain_age_days,
            "privacy_protected": True if w.org is None else False
        }

    except Exception as e:
        return {
            "domain": domain if 'domain' in locals() else "unknown",
            "creation_date": "unknown",
            "expiration_date": "unknown",
            "registrar": "unknown",
            "registrant_country": "unknown",
            "domain_age_days": None,
            "privacy_protected": "unknown",
            "error": str(e)
        }

