from __future__ import annotations

from datetime import timedelta

from synthetic_security_dataset_generator.core.base_generator import BaseGenerator
from synthetic_security_dataset_generator.core.labeling_engine import LabelDecision
from synthetic_security_dataset_generator.utils.time_utils import isoformat, utc_now


LOCATIONS = [
    ("Chicago", "198.51.100"),
    ("New York", "198.51.101"),
    ("San Francisco", "198.51.102"),
    ("London", "203.0.113"),
    ("Singapore", "203.0.114"),
]

ACTIONS = ["login", "view_dashboard", "download_report", "update_profile", "logout"]

ANOMALIES = {
    "new_geo": "User logged in from a new geography outside their historical baseline.",
    "impossible_travel": "Two distant login locations occurred too close in time for legitimate travel.",
    "high_frequency_actions": "Session contains an unusual concentration of actions within a short time window.",
    "privilege_escalation": "User attempts privileged actions without matching role history.",
}


class UserBehaviorGenerator(BaseGenerator):
    dataset_name = "user_behavior"

    def generate_record(self, malicious: bool | None = None, attack_type: str | None = None) -> dict[str, object]:
        anomaly_type = attack_type or ("normal" if not malicious else self.random.choice(list(ANOMALIES)))
        user_id = f"user-{self.random.randint(1000, 9999)}"
        base_time = utc_now() - timedelta(hours=self.random.randint(1, 72))
        sequence = (
            self._normal_sequence(user_id, base_time)
            if anomaly_type == "normal"
            else self._anomalous_sequence(user_id, base_time, anomaly_type)
        )
        features = {
            "event_count": len(sequence),
            "distinct_locations": len({event["location"] for event in sequence}),
            "action_velocity": round(len(sequence) / max(sequence[-1]["offset_minutes"], 1), 4),
            "contains_admin_action": any(event["action"] == "grant_admin_role" for event in sequence),
        }
        decision = LabelDecision(
            label="normal" if anomaly_type == "normal" else "anomaly",
            category=anomaly_type,
            explanation=ANOMALIES.get(anomaly_type, "Routine user behavior."),
            features=features,
            metadata={"user_id": user_id, "source": "synthetic_behavior_engine"},
        )
        return self.labeling.attach({"user_id": user_id, "events": sequence}, decision)

    def _normal_sequence(self, user_id: str, base_time) -> list[dict[str, object]]:
        city, prefix = self.random.choice(LOCATIONS[:3])
        offset = 0
        events = []
        for action in ["login", "view_dashboard", "download_report", "logout"]:
            offset += self.random.randint(8, 30)
            events.append(self._event(user_id, base_time, city, prefix, action, offset))
        return events

    def _anomalous_sequence(self, user_id: str, base_time, anomaly_type: str) -> list[dict[str, object]]:
        if anomaly_type == "new_geo":
            home_city, home_prefix = self.random.choice(LOCATIONS[:2])
            away_city, away_prefix = self.random.choice(LOCATIONS[3:])
            return [
                self._event(user_id, base_time, home_city, home_prefix, "login", 0),
                self._event(user_id, base_time, away_city, away_prefix, "login", 420),
                self._event(user_id, base_time, away_city, away_prefix, "download_report", 430),
            ]
        if anomaly_type == "impossible_travel":
            first_city, first_prefix = self.random.choice(LOCATIONS[:2])
            second_city, second_prefix = self.random.choice(LOCATIONS[3:])
            return [
                self._event(user_id, base_time, first_city, first_prefix, "login", 0),
                self._event(user_id, base_time, second_city, second_prefix, "login", 25),
                self._event(user_id, base_time, second_city, second_prefix, "view_dashboard", 30),
            ]
        if anomaly_type == "high_frequency_actions":
            city, prefix = self.random.choice(LOCATIONS[:3])
            events = []
            offset = 0
            for _ in range(12):
                offset += self.random.randint(1, 2)
                events.append(self._event(user_id, base_time, city, prefix, self.random.choice(ACTIONS[:-1]), offset))
            return events
        city, prefix = self.random.choice(LOCATIONS[:3])
        return [
            self._event(user_id, base_time, city, prefix, "login", 0),
            self._event(user_id, base_time, city, prefix, "grant_admin_role", 3),
            self._event(user_id, base_time, city, prefix, "disable_mfa", 6),
        ]

    def _event(self, user_id: str, base_time, city: str, prefix: str, action: str, offset_minutes: int) -> dict[str, object]:
        return {
            "user_id": user_id,
            "timestamp": isoformat(base_time + timedelta(minutes=offset_minutes)),
            "offset_minutes": offset_minutes,
            "action": action,
            "location": city,
            "ip": f"{prefix}.{self.random.randint(1, 254)}",
        }
