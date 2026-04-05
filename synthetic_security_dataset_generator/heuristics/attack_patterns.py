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
}
