"""Plain helpers shared by the WAF audit tests (fixtures live in conftest.py)."""


def verdict(svc, body: str, direction: str = "outbound") -> dict:
    return svc._analyze_sync(body, False, direction)


def is_block(v: dict) -> bool:
    return str(v["status"]).lower().endswith("block")


def blocked(svc, body: str, direction: str = "outbound") -> bool:
    return is_block(verdict(svc, body, direction))


def target_blocked(svc, target: str) -> bool:
    return is_block(svc._analyze_target(target))
