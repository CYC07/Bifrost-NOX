"""Static rule-based filtering engine.

Evaluates manual Allow/Block rules BEFORE AI analysis so administrators can
enforce hard policy (IP/port/domain/keyword) without waiting on model inference.

Rules are persisted to JSON and evaluated in priority order (lowest number = highest priority).
First match wins. If no rule matches, verdict is None -> fall through to AI analysis.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, asdict, field, fields
from typing import Optional

logger = logging.getLogger("rule_engine")

RULES_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "firewall_rules.json")
)

VALID_ACTIONS = {"allow", "block"}
VALID_MATCH_TYPES = {"ip_src", "ip_dst", "port", "domain", "keyword"}


@dataclass
class Rule:
    id: str
    action: str            # "allow" | "block"
    match_type: str        # "ip_src" | "ip_dst" | "port" | "domain" | "keyword"
    value: str             # e.g. "192.168.1.50", "22", "example.com", "badword"
    priority: int = 100    # lower = evaluated first
    enabled: bool = True
    description: str = ""
    hits24h: int = 0
    updated: str = ""

    def matches(self, ctx: dict) -> bool:
        if not self.enabled:
            return False
        v = self.value.strip().lower()
        if self.match_type == "ip_src":
            return ctx.get("source_ip", "").lower() == v
        if self.match_type == "ip_dst":
            return ctx.get("destination_ip", "").lower() == v
        if self.match_type == "port":
            return str(ctx.get("port", "")) == v
        if self.match_type == "domain":
            host = ctx.get("destination_ip", "").lower()
            return v in host  # substring match on host/domain
        if self.match_type == "keyword":
            text = ctx.get("text_content", "").lower()
            return v in text
        return False


class RuleEngine:
    def __init__(self, path: str = RULES_PATH) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._rules: list[Rule] = []
        self._load()

    def _load(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if not os.path.exists(self.path):
            self._rules = []
            self._save()
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            allowed = {f.name for f in fields(Rule)}
            self._rules = [
                Rule(**{k: v for k, v in r.items() if k in allowed})
                for r in data.get("rules", [])
            ]
            logger.info(f"Loaded {len(self._rules)} static firewall rules")
        except Exception as exc:
            logger.error(f"Failed to load rules: {exc}")
            self._rules = []

    def _save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"rules": [asdict(r) for r in self._rules]}, f, indent=2)

    def list_rules(self) -> list[dict]:
        with self._lock:
            return [asdict(r) for r in sorted(self._rules, key=lambda r: r.priority)]

    def add_rule(
        self,
        action: str,
        match_type: str,
        value: str,
        priority: int = 100,
        enabled: bool = True,
        description: str = "",
    ) -> dict:
        action = action.lower().strip()
        match_type = match_type.lower().strip()
        if action not in VALID_ACTIONS:
            raise ValueError(f"action must be one of {VALID_ACTIONS}")
        if match_type not in VALID_MATCH_TYPES:
            raise ValueError(f"match_type must be one of {VALID_MATCH_TYPES}")
        if not value or not value.strip():
            raise ValueError("value is required")
        rule = Rule(
            id=uuid.uuid4().hex[:8],
            action=action,
            match_type=match_type,
            value=value.strip(),
            priority=int(priority),
            enabled=bool(enabled),
            description=description.strip(),
            hits24h=0,
            updated=datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        )
        with self._lock:
            self._rules.append(rule)
            self._save()
        logger.info(f"Rule added: {rule}")
        return asdict(rule)

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            changed = len(self._rules) != before
            if changed:
                self._save()
        return changed

    def toggle_rule(self, rule_id: str) -> Optional[dict]:
        with self._lock:
            for r in self._rules:
                if r.id == rule_id:
                    r.enabled = not r.enabled
                    r.updated = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
                    self._save()
                    return asdict(r)
        return None

    def evaluate(self, ctx: dict) -> Optional[dict]:
        """Return first matching rule (as dict) or None if nothing matches."""
        with self._lock:
            ordered = sorted(self._rules, key=lambda r: r.priority)
            for r in ordered:
                if r.matches(ctx):
                    r.hits24h += 1
                    logger.info(f"Rule hit: {r.id} ({r.action} {r.match_type}={r.value})")
                    return asdict(r)
        return None


_engine: Optional[RuleEngine] = None


def get_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine
