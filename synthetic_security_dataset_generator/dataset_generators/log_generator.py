from __future__ import annotations

from datetime import timedelta
from typing import Any

from synthetic_security_dataset_generator.core.base_generator import BaseGenerator
from synthetic_security_dataset_generator.core.labeling_engine import LabelDecision
from synthetic_security_dataset_generator.heuristics.attack_patterns import (
    ATTACK_CHAINS,
    ATTACK_SCENARIOS,
    ATTACK_STAGE_DETAILS,
    USER_AGENTS,
)
from synthetic_security_dataset_generator.utils.time_utils import isoformat, utc_now


class AttackLogGenerator(BaseGenerator):
    dataset_name = "logs"

    def generate_record(self, malicious: bool | None = None, attack_type: str | None = None) -> dict[str, Any]:
        label = "normal" if not malicious else attack_type or self.random.choice(list(ATTACK_CHAINS))
        session_id = self.random.sequence_id("sess")
        campaign_id = self.random.sequence_id("camp") if label != "normal" else None
        base_time = utc_now() - timedelta(minutes=self.random.randint(60, 720))
        events = self._build_normal_sequence(base_time, session_id, campaign_id)
        if label != "normal":
            events.extend(self._build_attack_chain(base_time + timedelta(minutes=15), session_id, campaign_id, label))

        status_codes = [event["status_code"] for event in events]
        attack_stages = [event["attack_stage"] for event in events]
        features = {
            "request_count": len(events),
            "unique_endpoints": len({event["endpoint"] for event in events}),
            "error_rate": round(sum(code >= 400 for code in status_codes) / len(status_codes), 4),
            "duration_seconds": events[-1]["offset_seconds"],
            "attack_stage_count": len({stage for stage in attack_stages if stage != "normal"}),
            "distinct_ips": len({event["ip"] for event in events}),
        }
        decision = LabelDecision(
            label=label,
            category=label,
            explanation=ATTACK_SCENARIOS.get(label, "Routine user-driven traffic pattern with ambient noise."),
            features=features,
            metadata={"session_id": session_id, "campaign_id": campaign_id, "source": "synthetic_log_engine"},
        )
        return self.labeling.attach({"session_id": session_id, "campaign_id": campaign_id, "events": events}, decision)

    def _build_normal_sequence(self, base_time, session_id: str, campaign_id: str | None) -> list[dict[str, Any]]:
        count = self.random.randint(5, 8)
        entries = []
        offset = 0
        ip = self._ip("198.51.100")
        previous_event_id = None
        for _ in range(count):
            offset += self.random.randint(10, 90)
            event = self._event(
                base_time,
                session_id,
                ip,
                self.random.choice(["/", "/login", "/api/v1/session", "/dashboard", "/reports"]),
                self.random.choice([200, 200, 200, 302]),
                self.random.choice(USER_AGENTS),
                offset,
                attack_stage="normal",
                previous_event_id=previous_event_id,
                campaign_id=campaign_id,
            )
            previous_event_id = event["event_id"]
            entries.append(event)
        return entries

    def _build_attack_chain(self, base_time, session_id: str, campaign_id: str | None, chain_name: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        offset = 0
        previous_event_id = None
        current_ip = self._ip("203.0.113")
        for stage in ATTACK_CHAINS[chain_name]:
            stage_detail = ATTACK_STAGE_DETAILS[stage]
            stage_count = self.random.randint(2, 5)
            if stage in {"lateral_movement", "data_exfiltration"}:
                current_ip = self._ip("10.10.20")
            elif stage in {"recon", "scan"}:
                current_ip = self._ip("45.83.64")
            else:
                current_ip = self._ip("185.220.101")
            for _ in range(stage_count):
                offset += self.random.randint(4, 60 if stage in {"recon", "scan"} else 20)
                endpoint = self.random.choice(stage_detail["endpoints"])
                status_code = self.random.choice(stage_detail["codes"])
                event = self._event(
                    base_time,
                    session_id,
                    current_ip,
                    endpoint,
                    status_code,
                    self.random.choice(USER_AGENTS),
                    offset,
                    user=self.random.choice(["admin", "root", "ubuntu", "svc-backup"]),
                    method="POST" if "login" in endpoint or "session" in endpoint else "GET",
                    bytes_sent=self.random.randint(4096, 125000) if stage == "data_exfiltration" else None,
                    attack_stage=stage,
                    previous_event_id=previous_event_id,
                    campaign_id=campaign_id,
                )
                previous_event_id = event["event_id"]
                events.append(event)
        return events

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
        attack_stage: str = "normal",
        previous_event_id: str | None = None,
        campaign_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "event_id": self.random.sequence_id("evt"),
            "session_id": session_id,
            "campaign_id": campaign_id,
            "timestamp": isoformat(base_time + timedelta(seconds=offset)),
            "offset_seconds": offset,
            "ip": ip,
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "user_agent": user_agent,
            "user": user,
            "bytes_sent": bytes_sent if bytes_sent is not None else self.random.randint(256, 8192),
            "attack_stage": attack_stage,
            "previous_event_id": previous_event_id,
        }

    def _ip(self, prefix: str) -> str:
        return f"{prefix}.{self.random.randint(1, 254)}"
