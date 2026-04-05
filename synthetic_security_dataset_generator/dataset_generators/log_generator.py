from __future__ import annotations

from datetime import timedelta
from typing import Any

from synthetic_security_dataset_generator.core.base_generator import BaseGenerator
from synthetic_security_dataset_generator.core.labeling_engine import LabelDecision
from synthetic_security_dataset_generator.heuristics.attack_patterns import (
    ATTACK_SCENARIOS,
    ENDPOINTS,
    SSH_USERS,
    STATUS_CODES,
    USER_AGENTS,
)
from synthetic_security_dataset_generator.utils.time_utils import isoformat, utc_now


class AttackLogGenerator(BaseGenerator):
    dataset_name = "logs"

    def generate_record(self, malicious: bool | None = None, attack_type: str | None = None) -> dict[str, Any]:
        attack_type = attack_type or ("normal" if not malicious else self.random.choice(list(ATTACK_SCENARIOS)))
        session_id = self.random.sequence_id("sess")
        base_time = utc_now() - timedelta(minutes=self.random.randint(1, 300))
        entries = (
            self._build_normal_sequence(base_time, session_id)
            if attack_type == "normal"
            else self._build_attack_sequence(base_time, session_id, attack_type)
        )
        status_codes = [entry["status_code"] for entry in entries]
        features = {
            "request_count": len(entries),
            "unique_endpoints": len({entry["endpoint"] for entry in entries}),
            "error_rate": round(sum(code >= 400 for code in status_codes) / len(status_codes), 4),
            "duration_seconds": entries[-1]["offset_seconds"],
        }
        decision = LabelDecision(
            label="normal" if attack_type == "normal" else attack_type,
            category=attack_type,
            explanation=ATTACK_SCENARIOS.get(attack_type, "Benign user-driven traffic pattern."),
            features=features,
            metadata={"session_id": session_id, "source": "synthetic_log_engine"},
        )
        return self.labeling.attach({"session_id": session_id, "events": entries}, decision)

    def _build_normal_sequence(self, base_time, session_id: str) -> list[dict[str, Any]]:
        count = self.random.randint(4, 8)
        entries = []
        offset = 0
        ip = self._ip("198.51.100")
        for _ in range(count):
            offset += self.random.randint(6, 40)
            entries.append(
                self._event(
                    base_time,
                    session_id,
                    ip,
                    self.random.choice(["/", "/login", "/api/v1/session", "/dashboard"]),
                    self.random.choice([200, 200, 200, 302]),
                    self.random.choice(USER_AGENTS),
                    offset,
                )
            )
        return entries

    def _build_attack_sequence(self, base_time, session_id: str, attack_type: str) -> list[dict[str, Any]]:
        if attack_type == "brute_force":
            count, ip, endpoints, codes, step = 14, self._ip("203.0.113"), ["/login", "/ssh/auth"], [401, 401, 403], 3
        elif attack_type == "credential_stuffing":
            count, ip, endpoints, codes, step = 18, self._ip("203.0.113"), ["/login", "/api/v1/session"], [401, 401, 200], 4
        elif attack_type == "scan":
            count, ip, endpoints, codes, step = 16, self._ip("45.83.64"), ENDPOINTS, [404, 403, 404, 200], 2
        elif attack_type == "ddos":
            count, ip, endpoints, codes, step = 28, self._ip("192.0.2"), ["/", "/api/v1/session"], [200, 502, 503], 1
        else:
            count, ip, endpoints, codes, step = 10, self._ip("185.220.101"), ["/admin", "/backup.tar.gz", "/metrics"], [401, 403, 404], 5

        entries = []
        offset = 0
        for index in range(count):
            offset += self.random.randint(1, step)
            user = self.random.choice(SSH_USERS)
            ua = self.random.choice(USER_AGENTS if attack_type != "credential_stuffing" else USER_AGENTS[:3])
            entries.append(
                self._event(
                    base_time,
                    session_id,
                    ip,
                    self.random.choice(endpoints),
                    self.random.choice(codes),
                    ua,
                    offset,
                    user=user,
                    method="POST" if "/login" in self.random.choice(endpoints) else "GET",
                    bytes_sent=self.random.randint(128, 4096) if attack_type != "ddos" else self.random.randint(1024, 65535),
                )
            )
            if attack_type == "credential_stuffing" and index % 5 == 0:
                ip = self._ip("198.18.0")
        return entries

    def _event(
        self,
        base_time,
        session_id: str,
        ip: str,
        endpoint: str,
        status_code: int,
        user_agent: str,
        offset: int,
        user: str | None = None,
        method: str = "GET",
        bytes_sent: int | None = None,
    ) -> dict[str, Any]:
        return {
            "session_id": session_id,
            "timestamp": isoformat(base_time + timedelta(seconds=offset)),
            "offset_seconds": offset,
            "ip": ip,
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "user_agent": user_agent,
            "user": user,
            "bytes_sent": bytes_sent if bytes_sent is not None else self.random.randint(256, 8192),
        }

    def _ip(self, prefix: str) -> str:
        return f"{prefix}.{self.random.randint(1, 254)}"
