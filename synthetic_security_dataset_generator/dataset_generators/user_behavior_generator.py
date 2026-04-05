from __future__ import annotations

from datetime import timedelta
from typing import Any

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
    "slow_data_exfiltration": "User gradually downloads more data than their baseline over an extended session.",
}


class UserBehaviorGenerator(BaseGenerator):
    dataset_name = "user_behavior"

    def generate_record(self, malicious: bool | None = None, attack_type: str | None = None) -> dict[str, Any]:
        anomaly_type = attack_type or ("normal" if not malicious else self.random.choice(list(ANOMALIES)))
        baseline = self._build_baseline()
        user_id = f"user-{self.random.randint(1000, 9999)}"
        base_time = self._sample_session_time(baseline)
        history_summary = self._history_summary(baseline)
        sequence = (
            self._normal_sequence(user_id, base_time, baseline)
            if anomaly_type == "normal"
            else self._anomalous_sequence(user_id, base_time, baseline, anomaly_type)
        )
        session_anomaly_score = round(sum(event["risk_score"] for event in sequence) / len(sequence), 4)
        features = {
            "event_count": len(sequence),
            "distinct_locations": len({event["location"] for event in sequence}),
            "action_velocity": round(len(sequence) / max(sequence[-1]["offset_minutes"], 1), 4),
            "contains_admin_action": any(event["action"] == "grant_admin_role" for event in sequence),
            "session_anomaly_score": session_anomaly_score,
            "baseline_location_count": len(baseline["common_locations"]),
            "weekend_session": base_time.weekday() >= 5,
            "history_days": history_summary["history_days"],
        }
        decision = LabelDecision(
            label="normal" if anomaly_type == "normal" else "anomaly",
            category=anomaly_type,
            explanation=ANOMALIES.get(anomaly_type, "Routine user behavior."),
            features=features,
            metadata={
                "user_id": user_id,
                "baseline": baseline,
                "history_summary": history_summary,
                "source": "synthetic_behavior_engine",
            },
        )
        return self.labeling.attach(
            {
                "user_id": user_id,
                "events": sequence,
                "history_summary": history_summary,
                "relationships": [{"src": user_id, "dst": event["ip"], "relation": "uses_ip"} for event in sequence],
            },
            decision,
        )

    def _build_baseline(self) -> dict[str, Any]:
        primary = self.random.choice(LOCATIONS[:3])
        secondary = self.random.choice(LOCATIONS[:3])
        avg_login_hour = self.random.randint(7, 10)
        avg_daily_actions = self.random.randint(4, 12)
        return {
            "common_locations": [primary[0], secondary[0]],
            "avg_login_hour_utc": avg_login_hour,
            "avg_daily_actions": avg_daily_actions,
            "usual_actions": ["login", "view_dashboard", "download_report", "logout"],
            "weekday_activity_bias": round(self.random.uniform(0.65, 0.9), 2),
            "weekend_activity_bias": round(self.random.uniform(0.1, 0.35), 2),
        }

    def _normal_sequence(self, user_id: str, base_time, baseline: dict[str, Any]) -> list[dict[str, Any]]:
        city_name = baseline["common_locations"][0]
        city, prefix = next(location for location in LOCATIONS if location[0] == city_name)
        offset = 0
        events = []
        for action in baseline["usual_actions"]:
            offset += self.random.randint(8, 40)
            events.append(self._event(user_id, base_time, city, prefix, action, offset, baseline))
        return events

    def _anomalous_sequence(
        self,
        user_id: str,
        base_time,
        baseline: dict[str, Any],
        anomaly_type: str,
    ) -> list[dict[str, Any]]:
        if anomaly_type == "new_geo":
            home_city, home_prefix = next(location for location in LOCATIONS if location[0] == baseline["common_locations"][0])
            away_city, away_prefix = self.random.choice(LOCATIONS[3:])
            return [
                self._event(user_id, base_time, home_city, home_prefix, "login", 0, baseline),
                self._event(user_id, base_time, away_city, away_prefix, "login", 420, baseline),
                self._event(user_id, base_time, away_city, away_prefix, "download_report", 430, baseline, data_volume_mb=150),
            ]
        if anomaly_type == "impossible_travel":
            first_city, first_prefix = next(location for location in LOCATIONS if location[0] == baseline["common_locations"][0])
            second_city, second_prefix = self.random.choice(LOCATIONS[3:])
            return [
                self._event(user_id, base_time, first_city, first_prefix, "login", 0, baseline),
                self._event(user_id, base_time, second_city, second_prefix, "login", 25, baseline),
                self._event(user_id, base_time, second_city, second_prefix, "view_dashboard", 30, baseline),
            ]
        if anomaly_type == "high_frequency_actions":
            city, prefix = next(location for location in LOCATIONS if location[0] == baseline["common_locations"][0])
            events = []
            offset = 0
            for _ in range(max(12, baseline["avg_daily_actions"] + 6)):
                offset += self.random.randint(1, 2)
                events.append(self._event(user_id, base_time, city, prefix, self.random.choice(ACTIONS[:-1]), offset, baseline))
            return events
        if anomaly_type == "slow_data_exfiltration":
            city, prefix = next(location for location in LOCATIONS if location[0] == baseline["common_locations"][0])
            offsets = [0, 60, 180, 360, 540]
            volumes = [20, 45, 90, 150, 240]
            return [
                self._event(user_id, base_time, city, prefix, "login", offsets[0], baseline),
                self._event(user_id, base_time, city, prefix, "download_report", offsets[1], baseline, data_volume_mb=volumes[1]),
                self._event(user_id, base_time, city, prefix, "download_report", offsets[2], baseline, data_volume_mb=volumes[2]),
                self._event(user_id, base_time, city, prefix, "download_report", offsets[3], baseline, data_volume_mb=volumes[3]),
                self._event(user_id, base_time, city, prefix, "logout", offsets[4], baseline, data_volume_mb=volumes[4]),
            ]
        city, prefix = next(location for location in LOCATIONS if location[0] == baseline["common_locations"][0])
        return [
            self._event(user_id, base_time, city, prefix, "login", 0, baseline),
            self._event(user_id, base_time, city, prefix, "grant_admin_role", 3, baseline),
            self._event(user_id, base_time, city, prefix, "disable_mfa", 6, baseline),
        ]

    def _event(
        self,
        user_id: str,
        base_time,
        city: str,
        prefix: str,
        action: str,
        offset_minutes: int,
        baseline: dict[str, Any],
        data_volume_mb: int = 0,
    ) -> dict[str, Any]:
        risk_score = self._risk_score(city, action, offset_minutes, baseline, data_volume_mb)
        return {
            "user_id": user_id,
            "timestamp": isoformat(base_time + timedelta(minutes=offset_minutes)),
            "offset_minutes": offset_minutes,
            "action": action,
            "location": city,
            "ip": f"{prefix}.{self.random.randint(1, 254)}",
            "risk_score": risk_score,
            "data_volume_mb": data_volume_mb,
            "hour_of_day_utc": (base_time + timedelta(minutes=offset_minutes)).hour,
            "day_of_week": (base_time + timedelta(minutes=offset_minutes)).strftime("%A"),
        }

    def _risk_score(
        self,
        city: str,
        action: str,
        offset_minutes: int,
        baseline: dict[str, Any],
        data_volume_mb: int,
    ) -> float:
        score = 0.05
        if city not in baseline["common_locations"]:
            score += 0.45
        if action in {"grant_admin_role", "disable_mfa"}:
            score += 0.5
        if offset_minutes < 5:
            score += 0.15
        if data_volume_mb > 100:
            score += min(data_volume_mb / 500, 0.4)
        return round(min(score, 0.99), 4)

    def _sample_session_time(self, baseline: dict[str, Any]):
        days_back = self.random.randint(14, 180)
        session = utc_now() - timedelta(days=days_back)
        bias = baseline["weekday_activity_bias"] if session.weekday() < 5 else baseline["weekend_activity_bias"]
        hour = baseline["avg_login_hour_utc"] if self.random.random() < bias else self.random.randint(0, 23)
        return session.replace(hour=hour, minute=self.random.randint(0, 50), second=0, microsecond=0)

    def _history_summary(self, baseline: dict[str, Any]) -> dict[str, Any]:
        history_days = self.random.randint(45, 365)
        return {
            "history_days": history_days,
            "avg_weekday_actions": baseline["avg_daily_actions"],
            "avg_weekend_actions": max(1, baseline["avg_daily_actions"] - self.random.randint(1, 3)),
            "common_login_hours": [baseline["avg_login_hour_utc"], min(23, baseline["avg_login_hour_utc"] + 1)],
        }
