SSH_USERS = ["admin", "root", "ubuntu", "svc-backup", "deploy", "jenkins"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/8.4.0",
    "python-requests/2.32",
    "Go-http-client/1.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]
ENDPOINTS = [
    "/",
    "/login",
    "/api/v1/session",
    "/admin",
    "/wp-login.php",
    "/.env",
    "/api/v1/users",
    "/metrics",
]
STATUS_CODES = [200, 200, 200, 301, 302, 401, 403, 404, 500]
ATTACK_SCENARIOS = {
    "brute_force": "Repeated authentication attempts against SSH and login endpoints from a single source.",
    "credential_stuffing": "Distributed login attempts using common usernames and mixed user agents.",
    "scan": "Broad probing across sensitive resources with high 404 and 403 rates.",
    "ddos": "Burst of high-frequency requests against a narrow set of endpoints.",
    "admin_probe": "Focused access attempts toward administrative endpoints and backup artifacts.",
    "intrusion_chain": "Multi-stage intrusion chain from reconnaissance through internal movement and data exfiltration.",
    "app_takeover": "Application account takeover chain combining reconnaissance, probing, credential abuse, and exfiltration.",
}

ATTACK_CHAINS = {
    "intrusion_chain": ["recon", "scan", "brute_force", "initial_access", "lateral_movement", "data_exfiltration"],
    "app_takeover": ["recon", "admin_probe", "credential_stuffing", "initial_access", "data_exfiltration"],
}

ATTACK_STAGE_DETAILS = {
    "recon": {"endpoints": ["/", "/robots.txt", "/sitemap.xml"], "codes": [200, 200, 301]},
    "scan": {"endpoints": ENDPOINTS, "codes": [404, 403, 404, 200]},
    "brute_force": {"endpoints": ["/login", "/ssh/auth"], "codes": [401, 401, 403, 200]},
    "credential_stuffing": {"endpoints": ["/login", "/api/v1/session"], "codes": [401, 401, 200]},
    "initial_access": {"endpoints": ["/dashboard", "/admin"], "codes": [200, 302]},
    "lateral_movement": {"endpoints": ["/admin", "/api/v1/users", "/internal/config"], "codes": [200, 403]},
    "data_exfiltration": {"endpoints": ["/reports/export", "/api/v1/users", "/backup.tar.gz"], "codes": [200, 206]},
    "admin_probe": {"endpoints": ["/admin", "/backup.tar.gz", "/metrics"], "codes": [401, 403, 404]},
}
