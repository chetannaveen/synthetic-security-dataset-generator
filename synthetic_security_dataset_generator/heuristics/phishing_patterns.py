BRANDS = [
    "microsoft",
    "google",
    "apple",
    "amazon",
    "paypal",
    "chase",
    "bankofamerica",
    "dropbox",
]

BENIGN_DOMAINS = [
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "nytimes.com",
    "wikipedia.org",
]

PHISHING_KEYWORDS = ["login", "verify", "update", "secure", "account", "billing", "support"]

TLDS = [".com", ".net", ".org", ".co", ".info", ".security"]
TLD_RISK_SCORES = {
    ".com": 0.2,
    ".org": 0.15,
    ".net": 0.25,
    ".co": 0.45,
    ".info": 0.72,
    ".security": 0.61,
    ".top": 0.82,
    ".support": 0.64,
}

TYPO_SWAPS = {
    "microsoft": "rnicrosoft",
    "google": "goog1e",
    "apple": "app1e",
    "amazon": "arnazon",
    "paypal": "paypa1",
    "dropbox": "dropb0x",
}

PUNYCODE_DOMAINS = [
    "xn--pple-43d.com",
    "xn--googl-fsa.net",
    "xn--rnicrosoft-3bh.com",
]

UNICODE_HOMOGLYPHS = {
    "microsoft": "micrоsoft",
    "google": "gооgle",
    "apple": "аррӏе",
    "amazon": "amazоn",
    "paypal": "paypaӏ",
}

WHOIS_REGISTRARS = [
    "NameSilo, LLC",
    "Porkbun LLC",
    "GoDaddy.com, LLC",
    "Cloudflare Registrar",
    "Tucows Domains Inc.",
]

HOSTING_ASNS = [
    {"asn": "AS9009", "provider": "M247", "infra": "unknown"},
    {"asn": "AS14061", "provider": "DigitalOcean", "infra": "cloud"},
    {"asn": "AS16509", "provider": "Amazon AWS", "infra": "cloud"},
    {"asn": "AS20473", "provider": "Choopa", "infra": "suspicious"},
    {"asn": "AS16276", "provider": "OVH SAS", "infra": "unknown"},
]

PATH_PATTERNS = [
    "/signin",
    "/account/verify",
    "/portal/update",
    "/auth/session/review",
    "/security/billing/confirm",
    "/helpdesk/ticket/identity-check",
]
