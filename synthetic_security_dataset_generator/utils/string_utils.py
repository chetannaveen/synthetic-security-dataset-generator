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


def has_unicode_chars(value: str) -> bool:
    return any(ord(char) > 127 for char in value)


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insertions = previous[j] + 1
            deletions = current[j - 1] + 1
            substitutions = previous[j - 1] + (left_char != right_char)
            current.append(min(insertions, deletions, substitutions))
        previous = current
    return previous[-1]
