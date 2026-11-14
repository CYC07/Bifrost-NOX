"""Carrier shapes: the same templates wrap clean and attack values.

The v1 model learned "JSON body -> sqli" and "HTML -> xss" because the clean class had no such
shapes. Every value (clean or attack) goes through the same recipe here, so a shape carries no
label information. HELD_OUT shapes are never used for training: they measure whether the model
generalises to carriers it has not seen.
"""
from __future__ import annotations

import json
import random
from typing import Callable
from urllib.parse import parse_qs, quote, quote_plus, unquote

KEYS = ["q", "search", "name", "title", "comment", "message", "id", "username", "email", "note",
        "text", "desc", "query", "value", "field1", "data", "input", "content", "ref", "page"]
_PATHS = ["/search", "/api/v1/items", "/profile/update", "/post/comment", "/items/view", "/submit", "/", "/user"]
_NOISE = ["a=1", "lang=en", "page=2", "sort=asc", "ref=home", "utm_source=news", "v=3"]


def _key(rng: random.Random) -> str:
    return rng.choice(KEYS)


def _bare(v, rng):
    return v


def _form(v, rng):
    parts = [rng.choice(_NOISE), f"{_key(rng)}={quote_plus(v)}", rng.choice(_NOISE)]
    rng.shuffle(parts)
    return "&".join(parts)


def _form_single(v, rng):
    return f"{_key(rng)}={v}"


def _urlquery(v, rng):
    return f"{rng.choice(_PATHS)}?{rng.choice(_NOISE)}&{_key(rng)}={quote(v, safe='')}"


def _urlquery_raw(v, rng):
    return f"{rng.choice(_PATHS)}?{_key(rng)}={v}"


def _json(v, rng):
    return json.dumps({_key(rng): v, "n": rng.randint(0, 999)})


def _json_nested(v, rng):
    return json.dumps({"data": {"items": [{_key(rng): v, "ok": True}], "meta": {"page": rng.randint(1, 9)}}})


def _json_array(v, rng):
    return json.dumps([v, rng.choice(["x", "y", "z"])])


def _html_attr(v, rng):
    return f'<a title="{v}">link</a>'


def _html_text(v, rng):
    return f"<p>{v}</p>"


_CRED_USERS = ["admin", "root", "guest", "test", "user", "demo", "alice", "john"]
_CRED_PASSES = ["password", "secret123", "admin123", "123456", "letmein", "qwerty", "changeme", "hunter2"]
_CRED_KEYS = [("username", "password"), ("user", "pass"), ("login", "passwd"), ("email", "password")]


def _login(v, rng):
    """A login body with the value in the username or password field, form or JSON. The same
    template carries clean values and attacks, so 'login form' is not a label shortcut."""
    uk, pk = rng.choice(_CRED_KEYS)
    u, p = rng.choice(_CRED_USERS), rng.choice(_CRED_PASSES)
    if rng.random() < 0.5:
        u = v
    else:
        p = v
    if rng.random() < 0.7:
        extra = rng.choice(["", "&remember=true", "&submit=Login", "&csrf_token=a1b2c3d4"])
        return f"{uk}={quote_plus(u)}&{pk}={quote_plus(p)}{extra}"
    return json.dumps({uk: u, pk: p})


def _cookie(v, rng):
    return f"sid=a1b2c3d4; theme=dark; {_key(rng)}={quote(v, safe='')}"


SHAPES: dict[str, Callable[[str, random.Random], str]] = {
    "bare": _bare,
    "form": _form,
    "form_single": _form_single,
    "urlquery": _urlquery,
    "urlquery_raw": _urlquery_raw,
    "json": _json,
    "json_nested": _json_nested,
    "json_array": _json_array,
    "html_attr": _html_attr,
    "login": _login,
    "html_text": _html_text,
    "cookie": _cookie,
}

# Never trained on; used only to measure out-of-distribution generalisation.
HELD_OUT: frozenset[str] = frozenset({"html_text", "cookie"})
TRAIN_SHAPES: list[str] = [s for s in SHAPES if s not in HELD_OUT and s != "bare"]


def _leaves(x, out):
    if isinstance(x, dict):
        for i in x.values():
            _leaves(i, out)
    elif isinstance(x, list):
        for i in x:
            _leaves(i, out)
    else:
        out.append(x)


def recover(shape: str, wrapped: str, value: str) -> str:
    """Pull the carried value back out of a wrapped string (used by tests and by the
    evaluation notebook to prove nothing was altered)."""
    if shape == "bare":
        return wrapped
    if shape == "login":
        try:
            leaves: list = []
            _leaves(json.loads(wrapped), leaves)
            return value if value in leaves else ""
        except ValueError:
            vals = [x for vs in parse_qs(wrapped, keep_blank_values=True).values() for x in vs]
            return value if value in vals else ""
    if shape in ("form", "urlquery"):
        q = wrapped.split("?", 1)[1] if shape == "urlquery" else wrapped
        vals = [x for vs in parse_qs(q, keep_blank_values=True).values() for x in vs]
        return value if value in vals else ""
    if shape in ("form_single", "urlquery_raw"):
        return wrapped.split("=", 1)[1] if "=" in wrapped else ""
    if shape.startswith("json"):
        leaves: list = []
        _leaves(json.loads(wrapped), leaves)
        return value if value in leaves else ""
    if shape == "html_attr":
        return wrapped[len('<a title="'):-len('">link</a>')]
    if shape == "html_text":
        return wrapped[len("<p>"):-len("</p>")]
    if shape == "cookie":
        return unquote(wrapped.rsplit("=", 1)[1])
    raise KeyError(shape)
