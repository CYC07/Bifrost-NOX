"""The gateway's handling of an upstream (origin server) that cannot be reached.

Before: the proxy accepted the client's connection, then waited on the OS connect timeout (about two
minutes) for an origin that never answered, closed the socket without a word, and (for https) logged
the failure as `PINNED-TLS`, which sent us hunting for certificate pinning that was not there.

Now: a bounded connect (UPSTREAM_CONNECT_TIMEOUT) with one retry, a clear 502 page the browser can
show (over TLS too, using the proxy's certificate), and an `UPSTREAM-FAIL` event that is not counted
as a block. `PINNED-TLS` stays reserved for a client that really rejects the proxy's certificate.
"""
import asyncio
import os
import ssl
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import mitm_engine  # noqa: E402

_REAL_OPEN = asyncio.open_connection          # the test's own client must not go through the spy


class _Inspector:
    """Records the events the proxy reports (no log_connection: that hook is optional)."""

    def __init__(self):
        self.blocks = []

    async def log_block(self, src, dst, port, host, reason, rule="PINNED-TLS", status="block"):
        self.blocks.append({"host": host, "port": port, "reason": reason, "rule": rule, "status": status})


def _free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _proxy(tmp_path, monkeypatch, dest=("127.0.0.1", None), inspector=None, timeout=0.3):
    monkeypatch.chdir(tmp_path)                   # CertificateAuthority writes ./gateway/certs
    proxy = mitm_engine.TransparentProxy(host="127.0.0.1", port=0, inspector=inspector)
    proxy.upstream_connect_timeout = timeout
    server = await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0)
    proxy.port = server.sockets[0].getsockname()[1]
    dest_ip, dest_port = dest
    dest_port = dest_port or _free_port()          # a port nobody listens on: connection refused
    monkeypatch.setattr(proxy, "get_original_dest", lambda writer: (dest_ip, dest_port))
    return proxy, server


def _hang_then(monkeypatch, real_after):
    """Make the first `real_after` upstream dials hang forever, then behave normally. Returns the call log."""
    calls = []

    async def spy(host=None, port=None, *a, **k):
        calls.append((host, port))
        if len(calls) <= real_after:
            await asyncio.sleep(3600)              # a SYN that is never answered
        return await _REAL_OPEN(host, port, *a, **k)
    monkeypatch.setattr(mitm_engine.asyncio, "open_connection", spy)
    return calls


def _always_hang(monkeypatch):
    calls = []

    async def spy(host=None, port=None, *a, **k):
        calls.append((host, port))
        await asyncio.sleep(3600)
    monkeypatch.setattr(mitm_engine.asyncio, "open_connection", spy)
    return calls


# ---------------------------------------------------------------- bounded connect + one retry

def test_connect_retries_once_after_a_timeout(tmp_path, monkeypatch):
    async def scenario():
        listener = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        proxy, server = await _proxy(tmp_path, monkeypatch)
        calls = _hang_then(monkeypatch, 1)
        r, w = await proxy._open_upstream("127.0.0.1", port)
        w.close()
        listener.close(), server.close()
        return calls

    assert len(asyncio.run(scenario())) == 2         # first timed out, the retry connected


def test_connect_gives_up_after_the_retry_and_is_bounded(tmp_path, monkeypatch):
    async def scenario():
        proxy, server = await _proxy(tmp_path, monkeypatch, timeout=0.2)
        calls = _always_hang(monkeypatch)
        t0 = asyncio.get_running_loop().time()
        with pytest.raises(mitm_engine.UpstreamError) as ei:
            await proxy._open_upstream("203.0.113.9", 443)
        elapsed = asyncio.get_running_loop().time() - t0
        server.close()
        return calls, elapsed, str(ei.value)

    calls, elapsed, msg = asyncio.run(scenario())
    assert len(calls) == 2                            # one attempt + one retry, never more
    assert elapsed < 2.0                              # bounded by the timeout, not the OS
    assert "203.0.113.9" in msg and "timed out" in msg.lower()


def test_connection_refused_is_not_retried(tmp_path, monkeypatch):
    async def scenario():
        proxy, server = await _proxy(tmp_path, monkeypatch)
        calls = []
        real = asyncio.open_connection

        async def spy(host=None, port=None, *a, **k):
            calls.append(port)
            return await real(host, port, *a, **k)
        monkeypatch.setattr(mitm_engine.asyncio, "open_connection", spy)
        with pytest.raises(mitm_engine.UpstreamError) as ei:
            await proxy._open_upstream("127.0.0.1", _free_port())
        server.close()
        return calls, str(ei.value)

    calls, msg = asyncio.run(scenario())
    assert len(calls) == 1                            # a refusal is an answer: retrying cannot change it
    assert "refused" in msg.lower()


def test_timeout_and_retry_are_configurable(monkeypatch):
    monkeypatch.setenv("UPSTREAM_CONNECT_TIMEOUT", "2.5")
    monkeypatch.setenv("UPSTREAM_CONNECT_RETRIES", "0")
    assert mitm_engine._upstream_timeout() == 2.5
    assert mitm_engine._upstream_retries() == 0
    monkeypatch.setenv("UPSTREAM_CONNECT_TIMEOUT", "garbage")
    monkeypatch.setenv("UPSTREAM_CONNECT_RETRIES", "-3")
    assert mitm_engine._upstream_timeout() == 5.0     # default
    assert mitm_engine._upstream_retries() == 0       # never negative


# ---------------------------------------------------------------- plain http

def test_http_upstream_failure_returns_a_clear_502_and_logs_upstream_fail(tmp_path, monkeypatch):
    async def scenario():
        insp = _Inspector()
        proxy, server = await _proxy(tmp_path, monkeypatch, inspector=insp)
        r, w = await _REAL_OPEN("127.0.0.1", proxy.port)
        w.write(b"GET /doLogin HTTP/1.1\r\nHost: demo.example.test\r\n\r\n")
        await w.drain()
        data = await asyncio.wait_for(r.read(65536), 5)
        w.close()
        server.close()
        return data, insp.blocks

    data, events = asyncio.run(scenario())
    head, _, body = data.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 502")
    assert b"content-length: %d" % len(body) in head.lower()
    assert b"Bifrost" in body and b"could not reach" in body.lower()
    assert [e["rule"] for e in events] == ["UPSTREAM-FAIL"]
    assert events[0]["status"] == "allow"             # it failed; the firewall did not block anything


# ---------------------------------------------------------------- https

def _client_ctx(proxy, trust):
    ctx = ssl.create_default_context(cafile=proxy.ca.ca_cert_path) if trust else ssl.create_default_context()
    # Python 3.13+ verifies strictly and rejects the proxy's leaf certs for lacking an Authority Key
    # Identifier (browsers accept them). Not what is under test here, so relax that one flag.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def test_https_upstream_failure_still_gets_a_readable_502_over_tls(tmp_path, monkeypatch):
    async def scenario():
        insp = _Inspector()
        proxy, server = await _proxy(tmp_path, monkeypatch, inspector=insp)
        r, w = await _REAL_OPEN("127.0.0.1", proxy.port, ssl=_client_ctx(proxy, True),
                                server_hostname="origin.example.test")
        w.write(b"GET / HTTP/1.1\r\nHost: origin.example.test\r\n\r\n")
        await w.drain()
        data = await asyncio.wait_for(r.read(65536), 8)
        w.close()
        server.close()
        return data, insp.blocks

    data, events = asyncio.run(scenario())
    assert data.startswith(b"HTTP/1.1 502")
    assert b"origin.example.test" in data
    assert [e["rule"] for e in events] == ["UPSTREAM-FAIL"]


def test_client_that_rejects_the_proxy_cert_is_still_pinned_tls(tmp_path, monkeypatch):
    """The upstream is fine; the client refuses our certificate. That (and only that) is PINNED-TLS."""
    async def scenario():
        insp = _Inspector()
        listener = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)   # accepts, says nothing
        up_port = listener.sockets[0].getsockname()[1]
        proxy, server = await _proxy(tmp_path, monkeypatch, dest=("127.0.0.1", up_port), inspector=insp)

        async def plain_upstream(self_, ip, port, ssl_ctx=None, server_hostname=None):
            return await _REAL_OPEN(ip, port)             # skip TLS to the dummy upstream
        monkeypatch.setattr(mitm_engine.TransparentProxy, "_open_upstream", plain_upstream)

        with pytest.raises(ssl.SSLError):                  # default trust store: our CA is unknown -> rejected
            await _REAL_OPEN("127.0.0.1", proxy.port, ssl=_client_ctx(proxy, False),
                             server_hostname="pinned.example.test")
        await asyncio.sleep(0.3)
        listener.close(), server.close()
        return insp.blocks

    assert [e["rule"] for e in asyncio.run(scenario())] == ["PINNED-TLS"]


def test_a_failure_inside_the_pipe_is_not_reported_as_pinning(tmp_path, monkeypatch):
    async def scenario():
        insp = _Inspector()
        listener = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        up_port = listener.sockets[0].getsockname()[1]
        proxy, server = await _proxy(tmp_path, monkeypatch, dest=("127.0.0.1", up_port), inspector=insp)

        async def plain_upstream(self_, ip, port, ssl_ctx=None, server_hostname=None):
            return await _REAL_OPEN(ip, port)
        monkeypatch.setattr(mitm_engine.TransparentProxy, "_open_upstream", plain_upstream)

        async def boom(*a, **k):
            raise RuntimeError("parser bug")
        monkeypatch.setattr(proxy, "pipe", boom)

        r, w = await _REAL_OPEN("127.0.0.1", proxy.port, ssl=_client_ctx(proxy, True),
                                server_hostname="ok.example.test")    # handshake succeeds
        await asyncio.sleep(0.3)
        w.close()
        listener.close(), server.close()
        return insp.blocks

    assert asyncio.run(scenario()) == []


# ---------------------------------------------------------------- allowlisted tunnel

def test_tunnel_failure_is_logged_and_does_not_hang(tmp_path, monkeypatch):
    async def scenario():
        insp = _Inspector()
        proxy, server = await _proxy(tmp_path, monkeypatch, inspector=insp)
        _always_hang(monkeypatch)
        client_w = type("W", (), {"close": lambda self: None})()
        t0 = asyncio.get_running_loop().time()
        await proxy.tunnel_through(None, client_w, "203.0.113.9", 443, "pinned.example", "10.0.0.2")
        elapsed = asyncio.get_running_loop().time() - t0
        server.close()
        return elapsed, insp.blocks

    elapsed, events = asyncio.run(scenario())
    assert elapsed < 2.0
    assert [e["rule"] for e in events] == ["UPSTREAM-FAIL"]


# ---------------------------------------------------------------- review follow-ups

def _client_hello(server_name: str) -> bytes:
    """The bytes a TLS client sends first, with an arbitrary SNI (the ssl module lets a client send e.g. '/x')."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out = ssl.MemoryBIO()
    obj = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname=server_name)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def test_hostile_sni_cannot_make_the_proxy_write_files_outside_its_cert_dir(tmp_path, monkeypatch):
    import shutil
    import tempfile
    victim_dir = tempfile.mkdtemp(prefix="pw", dir="/tmp")    # short path: the ssl module refuses labels > 63 chars

    async def scenario():
        insp = _Inspector()
        proxy, server = await _proxy(tmp_path, monkeypatch, inspector=insp)
        target = os.path.join(victim_dir, "pwned")            # an absolute path used as the SNI
        r, w = await _REAL_OPEN("127.0.0.1", proxy.port)
        w.write(_client_hello(target))
        await w.drain()
        await asyncio.sleep(0.5)
        w.close()
        await asyncio.sleep(0.3)
        server.close()
        return target, insp.blocks

    try:
        target, events = asyncio.run(scenario())
        assert os.listdir(victim_dir) == []                   # nothing written where the SNI pointed
        assert not os.path.exists(target + ".crt") and not os.path.exists(target + ".key")
    finally:
        shutil.rmtree(victim_dir, ignore_errors=True)
    assert [e["rule"] for e in events] == ["UPSTREAM-FAIL"]   # treated as a connection with no usable SNI


@pytest.mark.parametrize("bad", [".x", "a" * 70 + ".com", "x\x00y"])
def test_unencodable_sni_becomes_an_upstream_error_not_a_crash(tmp_path, monkeypatch, bad):
    async def scenario():
        listener = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        proxy, server = await _proxy(tmp_path, monkeypatch)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with pytest.raises(mitm_engine.UpstreamError):
                await proxy._open_upstream("127.0.0.1", port, ctx, bad)
        finally:
            listener.close(), server.close()

    asyncio.run(scenario())


class _FakeReader:
    def __init__(self):
        self.reads = 0

    async def read(self, n=-1):
        self.reads += 1
        return b"GET / HTTP/1.1\r\n\r\n"


class _FakeWriter:
    def __init__(self):
        self.out, self.closed = b"", False

    def write(self, data):
        self.out += data

    async def drain(self):
        pass

    def close(self):
        self.closed = True


def test_502_reads_the_request_before_closing_so_the_client_does_not_get_a_reset(tmp_path, monkeypatch):
    """Closing with the request still unread makes the kernel send RST, and some clients then discard the 502."""
    async def scenario():
        proxy, server = await _proxy(tmp_path, monkeypatch)
        reader, writer = _FakeReader(), _FakeWriter()
        await proxy._reply_502(writer, "h.example", mitm_engine.UpstreamError("x"), reader)
        server.close()
        return reader, writer

    reader, writer = asyncio.run(scenario())
    assert reader.reads == 1 and writer.out.startswith(b"HTTP/1.1 502") and writer.closed


def test_a_slow_event_log_does_not_delay_the_502(tmp_path, monkeypatch):
    class SlowInspector(_Inspector):
        async def log_block(self, *a, **k):
            await asyncio.sleep(2)
            await super().log_block(*a, **k)

    async def scenario():
        proxy, server = await _proxy(tmp_path, monkeypatch, inspector=SlowInspector())
        r, w = await _REAL_OPEN("127.0.0.1", proxy.port)
        w.write(b"GET / HTTP/1.1\r\nHost: x.example.test\r\n\r\n")
        await w.drain()
        t0 = asyncio.get_running_loop().time()
        data = await asyncio.wait_for(r.read(65536), 5)
        elapsed = asyncio.get_running_loop().time() - t0
        w.close()
        server.close()
        return data, elapsed

    data, elapsed = asyncio.run(scenario())
    assert data.startswith(b"HTTP/1.1 502") and elapsed < 1.0


def test_a_silent_client_cannot_hold_the_502_over_tls_path_open(tmp_path, monkeypatch):
    """A client that sends a TLS-looking byte and then nothing must not pin a socket for the default 60 s."""
    async def scenario():
        proxy, server = await _proxy(tmp_path, monkeypatch)
        proxy.tls_handshake_timeout = 0.5
        r, w = await _REAL_OPEN("127.0.0.1", proxy.port)
        w.write(b"\x16")                                     # looks like the start of a TLS record, then silence
        await w.drain()
        t0 = asyncio.get_running_loop().time()
        data = await asyncio.wait_for(r.read(65536), 5)      # b"" once the proxy gives up and closes
        elapsed = asyncio.get_running_loop().time() - t0
        w.close()
        server.close()
        return data, elapsed

    data, elapsed = asyncio.run(scenario())
    assert data == b"" and elapsed < 3.0


def test_certificate_generation_failure_is_not_reported_as_pinning(tmp_path, monkeypatch):
    async def scenario():
        insp = _Inspector()
        listener = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        up_port = listener.sockets[0].getsockname()[1]
        proxy, server = await _proxy(tmp_path, monkeypatch, dest=("127.0.0.1", up_port), inspector=insp)

        async def plain_upstream(self_, ip, port, ssl_ctx=None, server_hostname=None):
            return await _REAL_OPEN(ip, port)
        monkeypatch.setattr(mitm_engine.TransparentProxy, "_open_upstream", plain_upstream)

        def disk_full(host):
            raise OSError(28, "No space left on device")
        monkeypatch.setattr(proxy.ca, "get_certificate_for_host", disk_full)

        r, w = await _REAL_OPEN("127.0.0.1", proxy.port)
        w.write(_client_hello("ok.example.test"))
        await w.drain()
        await asyncio.sleep(0.5)
        w.close()
        listener.close(), server.close()
        return insp.blocks

    assert asyncio.run(scenario()) == []                      # an internal fault is not the client's doing
