from __future__ import annotations

from datetime import timedelta
from typing import Any

from synthetic_security_dataset_generator.core.base_generator import BaseGenerator
from synthetic_security_dataset_generator.core.labeling_engine import LabelDecision
from synthetic_security_dataset_generator.heuristics.phishing_patterns import (
    BENIGN_DOMAINS,
    BRANDS,
    HOSTING_ASNS,
    PATH_PATTERNS,
    PHISHING_KEYWORDS,
    PUNYCODE_DOMAINS,
    TLDS,
    TLD_RISK_SCORES,
    TYPO_SWAPS,
    UNICODE_HOMOGLYPHS,
    WHOIS_REGISTRARS,
)
from synthetic_security_dataset_generator.utils.entropy_utils import shannon_entropy
from synthetic_security_dataset_generator.utils.string_utils import (
    count_subdomains,
    extract_domain,
    has_unicode_chars,
    levenshtein_distance,
)
from synthetic_security_dataset_generator.utils.time_utils import isoformat, utc_now


class PhishingURLGenerator(BaseGenerator):
    dataset_name = "phishing"

    def build_balance_plan(self) -> list[bool | None]:
        malicious = int(self.config.count * self.config.malicious_ratio)
        suspicious = int(self.config.count * self.config.suspicious_ratio)
        benign = self.config.count - malicious - suspicious
        plan: list[bool | None] = [True] * malicious + [None] * suspicious + [False] * benign
        return self.random.shuffle(plan)

    def generate_record(self, malicious: bool | None = None, attack_type: str | None = None) -> dict[str, Any]:
        if malicious is True:
            attack_type = attack_type or self.random.choice(
                ["typosquatting", "subdomain_abuse", "keyword_abuse", "punycode", "homoglyph"]
            )
            url, brand = self._make_malicious_url(attack_type)
            label = "phishing"
        elif malicious is None:
            attack_type = "suspicious_pattern"
            url, brand = self._make_suspicious_url()
            label = "suspicious"
        else:
            attack_type = "legitimate"
            url, brand = self._make_benign_url()
            label = "benign"

        domain = extract_domain(url)
        tld = f".{domain.split('.')[-1]}"
        matched_brand = brand or min(BRANDS, key=lambda candidate: levenshtein_distance(domain, candidate))
        domain_age_days = self.random.randint(3, 45) if label != "benign" else self.random.randint(365, 6200)
        hosting = self._hosting_signal(label)
        path = url.split(domain, 1)[-1]
        features = {
            "domain_length": len(domain),
            "entropy": shannon_entropy(domain),
            "number_of_subdomains": count_subdomains(domain),
            "contains_keyword": any(keyword in url.lower() for keyword in PHISHING_KEYWORDS),
            "looks_like_brand": any(candidate in domain.lower() for candidate in BRANDS) or bool(brand),
            "levenshtein_distance_to_brand": levenshtein_distance(domain.replace(".", ""), matched_brand),
            "tld_risk_score": TLD_RISK_SCORES.get(tld, 0.5),
            "domain_age_days": domain_age_days,
            "has_unicode_chars": has_unicode_chars(domain),
            "path_depth": path.count("/"),
            "path_complexity": round(shannon_entropy(path), 4),
        }
        whois_metadata = self._whois_metadata(domain, domain_age_days, label)
        decision = LabelDecision(
            label=label,
            category=attack_type,
            explanation=self._explanation(label, attack_type, matched_brand, hosting["provider"], domain_age_days),
            features=features,
            metadata={
                "brand_target": matched_brand or None,
                "source": "synthetic_url_engine",
                "whois": whois_metadata,
                "hosting": hosting,
            },
        )
        return self.labeling.attach({"url": url}, decision)

    def _make_benign_url(self) -> tuple[str, str]:
        base = self.random.choice(BENIGN_DOMAINS)
        path = self.random.choice(["/", "/support/security", "/products", "/account/security", "/docs/api"])
        brand = next((candidate for candidate in BRANDS if candidate in base), base.split(".")[0])
        return f"https://{base}{path}", brand

    def _make_suspicious_url(self) -> tuple[str, str]:
        brand = self.random.choice(BRANDS)
        keyword = self.random.choice(PHISHING_KEYWORDS)
        tld = self.random.choice([".co", ".support", ".info"])
        return f"https://{brand}-{keyword}{tld}{self.random.choice(PATH_PATTERNS)}", brand

    def _make_malicious_url(self, attack_type: str) -> tuple[str, str]:
        brand = self.random.choice(BRANDS)
        keyword = self.random.choice(PHISHING_KEYWORDS)
        if attack_type == "typosquatting":
            host = f"{TYPO_SWAPS.get(brand, brand[:-1] + '1')}{self.random.choice(TLDS + ['.top'])}"
            return f"https://{host}{self.random.choice(PATH_PATTERNS)}", brand
        if attack_type == "subdomain_abuse":
            host = f"secure-{keyword}.{brand}.verify-user.com"
            return f"https://{host}/session/{self.random.token('abcdef0123456789', 8)}", brand
        if attack_type == "punycode":
            host = self.random.choice(PUNYCODE_DOMAINS)
            return f"https://{host}{self.random.choice(PATH_PATTERNS)}", brand
        if attack_type == "homoglyph":
            host = f"{UNICODE_HOMOGLYPHS.get(brand, brand)}{self.random.choice(['.com', '.support', '.info'])}"
            return f"https://{host}/identity/{keyword}", brand
        host = f"{brand}-{keyword}-portal{self.random.choice(['.co', '.info', '.support'])}"
        return f"https://{host}/account/review/{self.random.token('abcdef1234567890', 6)}", brand

    def _whois_metadata(self, domain: str, age_days: int, label: str) -> dict[str, Any]:
        created = utc_now() - timedelta(days=age_days)
        expiry = created + timedelta(days=365 if label != "benign" else 3650)
        privacy = label != "benign" or self.random.random() < 0.2
        return {
            "domain": domain,
            "registrar": self.random.choice(WHOIS_REGISTRARS),
            "created_at": isoformat(created),
            "updated_at": isoformat(created + timedelta(days=max(age_days // 4, 1))),
            "expiry_at": isoformat(expiry),
            "privacy_protection": privacy,
        }

    def _hosting_signal(self, label: str) -> dict[str, str]:
        if label == "benign":
            pool = [entry for entry in HOSTING_ASNS if entry["infra"] == "cloud"]
        else:
            pool = HOSTING_ASNS
        return self.random.choice(pool)

    def _explanation(self, label: str, attack_type: str, brand: str, provider: str, age_days: int) -> str:
        if label == "benign":
            return "URL aligns with a known legitimate property, older registration history, and mainstream hosting signals."
        if label == "suspicious":
            return (
                f"URL shows brand-adjacent wording for {brand}, elevated path complexity, and a relatively new registration "
                f"hosted via {provider}."
            )
        return (
            f"URL exhibits {attack_type} indicators targeting {brand}, with fresh domain registration ({age_days} days) "
            f"and hosting characteristics associated with abuse-prone infrastructure."
        )
