from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def extract_domain(url: str) -> str:
    return urlparse(url).netloc.lower()


def count_subdomains(domain: str) -> int:
    parts = domain.split(".")
    return max(len(parts) - 2, 0)


def looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
