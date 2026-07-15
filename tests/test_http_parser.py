"""Unit tests for the streaming HTTPParser.

Covers the framing cases that stall connections or skip inspection when handled
wrong: bodyless messages, Content-Length, chunked, gzip/deflate over chunked,
and pipelined keep-alive.
"""
import gzip
import os
import sys
import zlib

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway")))
from http_parser import HTTPParser  # noqa: E402


def test_get_request_completes_at_headers():
    p = HTTPParser(role="request")
    p.feed(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert p.message_complete
    assert p.method == "GET"
    assert p.path == "/index.html"
    assert p.body == b""


def test_request_with_content_length_body():
    p = HTTPParser(role="request")
    p.feed(b"POST /login HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello=world")
    assert p.message_complete
    assert p.body == b"hello=world"
    assert p.raw.endswith(b"hello=world")


def test_content_length_split_across_feeds():
    p = HTTPParser(role="response")
    p.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel")
    assert not p.message_complete
    p.feed(b"loworld")
    assert p.message_complete
    assert p.body == b"helloworld"


def test_response_204_has_no_body():
    p = HTTPParser(role="response")
    p.feed(b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n")
    assert p.message_complete
    assert p.status == 204
    assert p.body == b""


def test_response_304_has_no_body():
    p = HTTPParser(role="response")
    p.feed(b"HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\n\r\n")
    assert p.message_complete
    assert p.body == b""


def test_chunked_body_dechunked():
    p = HTTPParser(role="response")
    body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    p.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body)
    assert p.message_complete
    assert p.body == b"hello world"


def test_chunked_split_across_feeds():
    p = HTTPParser(role="response")
    p.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
    assert not p.message_complete
    p.feed(b"lo\r\n0\r\n\r\n")
    assert p.message_complete
    assert p.body == b"hello"


def test_gzip_over_chunked_is_inflated_for_inspection():
    """The advisor's case: gzip'd HTML delivered chunked must reach inspection
    as plain text, not binary_unknown."""
    html = b"<html><body>secret api_key=AKIAIOSFODNN7EXAMPLE</body></html>"
    gz = gzip.compress(html)
    chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(gz), gz)
    p = HTTPParser(role="response")
    p.feed(
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
        + chunked
    )
    assert p.message_complete
    assert p.body == html
    assert b"api_key" in p.body


def test_deflate_content_length_inflated():
    payload = b"sensitive internal financial report"
    deflated = zlib.compress(payload)
    p = HTTPParser(role="response")
    header = b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: %d\r\n\r\n" % len(deflated)
    p.feed(header + deflated)
    assert p.message_complete
    assert p.body == payload


def test_pipelined_requests_leftover():
    p = HTTPParser(role="request")
    two = (
        b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
        b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    p.feed(two)
    assert p.message_complete
    assert p.path == "/a"
    leftover = p.take_leftover()
    assert leftover.startswith(b"GET /b")

    p.reset()
    p.feed(leftover)
    assert p.message_complete
    assert p.path == "/b"


def test_close_framed_response_finalizes_on_eof():
    p = HTTPParser(role="response")
    p.feed(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial")
    assert not p.message_complete   # no CL/TE -> waits for close
    p.feed(b" body")
    p.feed_eof()
    assert p.message_complete
    assert p.body == b"partial body"


def test_raw_preserves_wire_bytes_for_forwarding():
    """raw must be the untouched wire message so we forward, not re-encode."""
    wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    p = HTTPParser(role="response")
    p.feed(wire)
    assert p.raw == wire
