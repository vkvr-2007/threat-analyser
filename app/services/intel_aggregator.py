from app.services.whois_service import get_whois_data
from app.services.ssl_service import get_ssl_certificate_info


def gather_intelligence(url: str) -> dict:
    """
    Collects and normalizes all intelligence signals
    """
    whois_data = get_whois_data(url)
    ssl_data = get_ssl_certificate_info(url)

    return {
        "whois": whois_data,
        "ssl": ssl_data
    }
