from __future__ import annotations

from typing import Any

from synthetic_security_dataset_generator.core.base_generator import BaseGenerator
from synthetic_security_dataset_generator.core.labeling_engine import LabelDecision
from synthetic_security_dataset_generator.heuristics.phishing_patterns import (
    BENIGN_DOMAINS,
    BRANDS,
    PHISHING_KEYWORDS,
    PUNYCODE_DOMAINS,
    TLDS,
    TYPO_SWAPS,
)
from synthetic_security_dataset_generator.utils.entropy_utils import shannon_entropy
from synthetic_security_dataset_generator.utils.string_utils import count_subdomains, extract_domain


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
                ["typosquatting", "subdomain_abuse", "keyword_abuse", "punycode"]
            )
            url = self._make_malicious_url(attack_type)
            label = "phishing"
        elif malicious is None:
            attack_type = "suspicious_pattern"
            url = self._make_suspicious_url()
            label = "suspicious"
        else:
            attack_type = "legitimate"
            url = self._make_benign_url()
            label = "benign"

        domain = extract_domain(url)
        brand = next((brand for brand in BRANDS if brand in domain), "")
        features = {
            "domain_length": len(domain),
            "entropy": shannon_entropy(domain),
            "number_of_subdomains": count_subdomains(domain),
            "contains_keyword": any(keyword in url.lower() for keyword in PHISHING_KEYWORDS),
            "looks_like_brand": bool(brand),
        }
        decision = LabelDecision(
            label=label,
            category=attack_type,
            explanation=self._explanation(label, attack_type, brand),
            features=features,
            metadata={"brand_target": brand or None, "source": "synthetic_url_engine"},
        )
        return self.labeling.attach({"url": url}, decision)

    def _make_benign_url(self) -> str:
        base = self.random.choice(BENIGN_DOMAINS)
        path = self.random.choice(["/", "/support", "/products", "/account/security", "/docs"])
        return f"https://{base}{path}"

    def _make_suspicious_url(self) -> str:
        brand = self.random.choice(BRANDS)
        keyword = self.random.choice(PHISHING_KEYWORDS)
        return f"https://{brand}-{keyword}{self.random.choice(TLDS)}/signin"

    def _make_malicious_url(self, attack_type: str) -> str:
        brand = self.random.choice(BRANDS)
        keyword = self.random.choice(PHISHING_KEYWORDS)
        if attack_type == "typosquatting":
            host = f"{TYPO_SWAPS.get(brand, brand[:-1] + '1')}{self.random.choice(TLDS)}"
            return f"https://{host}/{keyword}"
        if attack_type == "subdomain_abuse":
            host = f"secure-{keyword}.{brand}.verify-user.com"
            return f"https://{host}/session"
        if attack_type == "punycode":
            host = self.random.choice(PUNYCODE_DOMAINS)
            return f"https://{host}/{keyword}/index.html"
        host = f"{brand}-{keyword}-portal{self.random.choice(TLDS)}"
        return f"https://{host}/account/review"

    def _explanation(self, label: str, attack_type: str, brand: str) -> str:
        if label == "benign":
            return "URL structure aligns with a legitimate brand or common public web property."
        target = f" targeting {brand}" if brand else ""
        if label == "suspicious":
            return f"URL contains phishing-adjacent keywords and branding cues{target}, but without overt malicious indicators."
        return f"URL exhibits {attack_type} indicators{target}, consistent with phishing infrastructure."
