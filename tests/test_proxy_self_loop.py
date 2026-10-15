"""A client that connects straight to the transparent proxy (no iptables REDIRECT) must not make
the proxy dial itself.

SO_ORIGINAL_DST then returns the proxy's own address, and the proxy used to connect to
127.0.0.1:8080, which accepted, connected again, and so on: one `curl -x http://127.0.0.1:8080`
produced an unbounded connection storm (thousands of events per second, 100% CPU, the dashboard
filled with loopback "ALLOW" rows) until the process was restarted.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import mitm_engine  # noqa: E402


async def _start_proxy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                       # CertificateAuthority writes ./gateway/certs
    proxy = mitm_engine.TransparentProxy(host="127.0.0.1", port=0, inspector=None)
    server = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    proxy.port = server.sockets[0].getsockname()[1]
    # What the kernel reported in the live incident for a connection that was never redirected:
    # the original destination is the proxy's own address.
    monkeypatch.setattr(proxy, "get_original_dest", lambda writer: ("127.0.0.1", proxy.port))
    return proxy, server


_REAL_OPEN_CONNECTION = asyncio.open_connection     # the test's own client must not be counted


def _record_dials(monkeypatch):
    """Record every connection the PROXY opens (patches the module-global, so tests use
    _REAL_OPEN_CONNECTION for their own client)."""
    dialed = []

    async def spy(host=None, port=None, *a, **k):
        dialed.append((host, port))
        return await _REAL_OPEN_CONNECTION(host, port, *a, **k)
    monkeypatch.setattr(mitm_engine.asyncio, "open_connection", spy)
    return dialed


def test_direct_connection_is_refused_and_never_dials_itself(tmp_path, monkeypatch):
    async def scenario():
        proxy, server = await _start_proxy(tmp_path, monkeypatch)
        dialed = _record_dials(monkeypatch)
        r, w = await _REAL_OPEN_CONNECTION("127.0.0.1", proxy.port)
        w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        await w.drain()
        try:
            data = await asyncio.wait_for(r.read(4096), 3)
        except asyncio.TimeoutError:
            data = b"<timeout>"
        await asyncio.sleep(0.5)                       # a loop would have dialed again by now
        w.close()
        server.close()
        await server.wait_closed()
        return proxy.port, dialed, data

    port, dialed, data = asyncio.run(scenario())
    assert not [d for d in dialed if d[1] == port], f"proxy dialed itself: {dialed}"
    assert data != b"<timeout>"                        # closed or answered promptly
    assert data == b"" or data.startswith(b"HTTP/1.1 421")


def test_refusal_is_a_clear_http_response(tmp_path, monkeypatch):
    async def scenario():
        proxy, server = await _start_proxy(tmp_path, monkeypatch)
        r, w = await _REAL_OPEN_CONNECTION("127.0.0.1", proxy.port)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await w.drain()
        data = await asyncio.wait_for(r.read(4096), 3)
        w.close()
        server.close()
        await server.wait_closed()
        return data

    data = asyncio.run(scenario())
    assert data.startswith(b"HTTP/1.1 421") and b"transparent" in data.lower()


def test_is_self_logic(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = mitm_engine.TransparentProxy(host="0.0.0.0", port=8080, inspector=None)

    class W:
        def __init__(self, sockname):
            self._s = sockname

        def get_extra_info(self, k):
            return self._s if k == "sockname" else None

    w = W(("192.168.56.1", 8080))
    assert p._is_self("127.0.0.1", 8080, w)
    assert p._is_self("192.168.56.1", 8080, w)         # the firewall's own LAN address
    assert p._is_self("0.0.0.0", 8080, w)
    assert not p._is_self("93.184.216.34", 8080, w)    # an external host that happens to use 8080
    assert not p._is_self("127.0.0.1", 80, w)          # same host, different port
    assert not p._is_self("192.168.56.1", 443, w)
