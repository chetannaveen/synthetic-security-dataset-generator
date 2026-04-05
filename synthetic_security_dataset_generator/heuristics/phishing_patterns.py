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
