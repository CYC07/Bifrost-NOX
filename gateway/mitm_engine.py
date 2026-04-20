import asyncio
import os
import socket
import struct
import ssl
import sys
import logging
from cert_utils import CertificateAuthority
from http_parser import HTTPParser

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.allowlist import is_allowed as is_host_allowed  # noqa: E402

logger = logging.getLogger("mitm_engine")
SO_ORIGINAL_DST = 80

class TransparentProxy:
    def __init__(self, host='0.0.0.0', port=8080, inspector=None):
        self.host = host
        self.port = port
        self.inspector = inspector
        self.ca = CertificateAuthority()
        self.loop = asyncio.get_event_loop()

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        logger.info(f"Transparent Proxy Listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    def get_original_dest(self, writer):
        transport = writer.transport
        sock = transport.get_extra_info('socket')
        try:
            odst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port, raw_ip = struct.unpack("!2xH4s8x", odst)
            ip = socket.inet_ntoa(raw_ip)
            # Guard: if SO_ORIGINAL_DST returns our own gateway IP it means
            # REDIRECT was not actually applied (direct connection to proxy).
            local_name = sock.getsockname()[0] if sock.getsockname() else ""
            if ip == local_name:
                logger.warning(
                    f"SO_ORIGINAL_DST returned local IP {ip} — REDIRECT likely not applied"
                )
            return ip, port
        except Exception as exc:
            logger.error(f"SO_ORIGINAL_DST failed: {exc}")
            return None, None

    def extract_sni(self, raw_data):
        try:
            offset = 43 
            if len(raw_data) <= offset: return None
            sess_id_len = raw_data[offset]
            offset += 1 + sess_id_len
            
            if len(raw_data) <= offset + 2: return None
            cipher_len = struct.unpack("!H", raw_data[offset:offset+2])[0]
            offset += 2 + cipher_len
            
            if len(raw_data) <= offset + 1: return None
            comp_len = raw_data[offset]
            offset += 1 + comp_len
            
            if len(raw_data) <= offset + 2: return None
            ext_len = struct.unpack("!H", raw_data[offset:offset+2])[0]
            offset += 2
            
            end = offset + ext_len
            while offset < end and offset + 4 <= len(raw_data):
                etype, elen = struct.unpack("!HH", raw_data[offset:offset+4])
                offset += 4
                if etype == 0: # SNI
                    if len(raw_data) < offset + 5: return None
                    name_len = struct.unpack("!H", raw_data[offset+3:offset+5])[0]
                    return raw_data[offset+5:offset+5+name_len].decode("utf-8")
                offset += elen
        except:
            pass
        return None

    async def handle_client(self, client_reader, client_writer):
        dest_ip, dest_port = self.get_original_dest(client_writer)
        if not dest_ip:
            dest_ip = "127.0.0.1" 
            dest_port = 80 
            # client_writer.close(); return # Strict mode

        sock = client_writer.get_extra_info('socket')
        transport = client_writer.transport
        is_tls = False
        server_name = dest_ip

        # get_extra_info('socket') returns a TransportSocket wrapper that
        # intentionally hides recv(). Drop to the underlying raw socket so we
        # can MSG_PEEK at the kernel buffer.
        raw_sock = getattr(sock, '_sock', sock)

        # Pause asyncio's reads so the ClientHello stays in the kernel buffer
        # and MSG_PEEK can see it. Without this, asyncio drains the socket
        # into StreamReader during our await, and every peek returns empty.
        try:
            transport.pause_reading()
        except Exception:
            pass

        peek_data = b""
        try:
            for _ in range(30):  # up to ~1.5s for first bytes
                try:
                    peek_data = raw_sock.recv(4096, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                    if peek_data:
                        break
                except (BlockingIOError, OSError):
                    pass
                except Exception as exc:
                    logger.debug(f"peek failed: {exc}")
                    break
                await asyncio.sleep(0.05)

            if peek_data and peek_data[0] == 0x16:
                is_tls = True
                sni = self.extract_sni(peek_data)
                if sni:
                    server_name = sni
            elif dest_port == 443:
                # Port 443 with no handshake yet — still treat as TLS
                is_tls = True
        finally:
            try:
                transport.resume_reading()
            except Exception:
                pass

        logger.info(f"CONN: {client_writer.get_extra_info('peername')} -> {dest_ip}:{dest_port} TLS={is_tls} Host={server_name}")

        peer = client_writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "unknown"

        # Push a connection-level event to the dashboard so users see traffic
        # flowing even when the AI content-inspection path skips this request.
        if self.inspector and hasattr(self.inspector, "log_connection"):
            asyncio.create_task(
                self.inspector.log_connection(client_ip, dest_ip, dest_port, is_tls, server_name)
            )

        if is_tls and is_host_allowed(server_name):
            logger.info(f"ALLOWLIST bypass (no MITM): {server_name}")
            await self.tunnel_through(
                client_reader, client_writer, dest_ip, dest_port, server_name, client_ip
            )
            return

        if is_tls:
            await self.handle_https(client_reader, client_writer, dest_ip, dest_port, server_name, client_ip)
        else:
            await self.handle_http(client_reader, client_writer, dest_ip, dest_port, server_name, client_ip)

    async def tunnel_through(self, client_reader, client_writer, dest_ip, dest_port, server_name, client_ip):
        """Raw TCP passthrough for allowlisted cert-pinned apps.

        We do not touch the TLS stream — client and upstream server complete
        their handshake end-to-end, as if the proxy were a transparent router.
        """
        try:
            server_reader, server_writer = await asyncio.open_connection(dest_ip, dest_port)
        except Exception as exc:
            logger.error(f"Tunnel {server_name} -> {dest_ip}:{dest_port} failed: {exc}")
            try: client_writer.close()
            except: pass
            return

        async def relay(reader, writer):
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try: writer.close()
                except: pass

        await asyncio.gather(
            relay(client_reader, server_writer),
            relay(server_reader, client_writer),
        )

    async def handle_http(self, client_reader, client_writer, dest_ip, dest_port, server_name, client_ip):
        try:
            server_reader, server_writer = await asyncio.open_connection(dest_ip, dest_port)
        except Exception as e:
            logger.error(f"Upstream HTTP error: {e}")
            client_writer.close()
            return
        await self.pipe(client_reader, client_writer, server_reader, server_writer,
                        is_https=False, client_ip=client_ip, server_name=server_name,
                        dest_ip=dest_ip, dest_port=dest_port)

    async def handle_https(self, client_reader, client_writer, dest_ip, dest_port, server_name, client_ip):
        try:
            server_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            server_ctx.check_hostname = False
            server_ctx.verify_mode = ssl.CERT_NONE
            server_reader, server_writer = await asyncio.open_connection(dest_ip, dest_port, ssl=server_ctx, server_hostname=server_name)
        except Exception as exc:
            logger.warning(f"Upstream TLS to {server_name} failed: {exc}")
            await self._log_pinned_block(client_ip, dest_ip, dest_port, server_name, f"Upstream TLS rejected ({exc.__class__.__name__})")
            client_writer.close()
            return

        try:
            cert_path, key_path = self.ca.get_certificate_for_host(server_name)
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(cert_path, key_path)

            transport = client_writer.transport
            new_transport = await self.loop.start_tls(transport, transport.get_protocol(), ssl_ctx, server_side=True)

            reader_ssl = asyncio.StreamReader()
            protocol_ssl = asyncio.StreamReaderProtocol(reader_ssl)
            new_transport.set_protocol(protocol_ssl)
            writer_ssl = asyncio.StreamWriter(new_transport, protocol_ssl, reader_ssl, self.loop)

            await self.pipe(reader_ssl, writer_ssl, server_reader, server_writer,
                            is_https=True, client_ip=client_ip, server_name=server_name,
                            dest_ip=dest_ip, dest_port=dest_port)
        except Exception as e:
            # Most common cause: the client pinned the upstream cert and rejected
            # our locally-signed fake one. Surface this as a BLOCK so the operator
            # sees it on the dashboard and can add the host to the allowlist.
            logger.warning(f"TLS upgrade to client failed for {server_name}: {e}")
            await self._log_pinned_block(client_ip, dest_ip, dest_port, server_name, f"Client rejected MITM cert ({e.__class__.__name__}) — add host to allowlist to bypass")
            try: client_writer.close()
            except: pass
            try: server_writer.close()
            except: pass

    async def _log_pinned_block(self, client_ip, dest_ip, dest_port, server_name, reason):
        if not (self.inspector and hasattr(self.inspector, "log_block")):
            return
        try:
            await self.inspector.log_block(client_ip, dest_ip, dest_port, server_name, reason)
        except Exception:
            pass

    async def pipe(self, client_r, client_w, server_r, server_w, is_https,
                   client_ip="unknown", server_name="unknown", dest_ip="unknown", dest_port=""):
        # We need two parsers for HTTP traffic
        client_parser = HTTPParser()
        server_parser = HTTPParser()

        async def forward(reader, writer, parser, direction):
            try:
                msg_buffer = b""
                while True:
                    data = await reader.read(8192)
                    if not data: break
                    
                    # Logic: Buffer untill full HTTP message is ready OR streaming
                    if self.inspector:
                        parser.parse(data)
                        msg_buffer += data
                        
                        # Check header completion
                        if parser.header_done:
                            # if content length known and we have it all
                            if len(parser.body) >= parser.content_length:
                                # We have full message!
                                # Prefer the actual hostname the client wanted:
                                # - HTTPS: SNI (already in server_name)
                                # - HTTP:  Host header from parsed request
                                # Fall back to server_name (SNI/dest_ip) then raw dest_ip
                                host_header = (parser.headers.get("host", "") or "").split(":")[0].strip()
                                real_dst = host_header or server_name or dest_ip
                                if direction == "outbound":
                                    src, dst = client_ip, real_dst
                                else:
                                    src, dst = real_dst, client_ip
                                verdict = await self.inspector.inspect_full(
                                    parser.headers, parser.body, direction, is_https,
                                    src_ip=src, dst_ip=dst, dst_port=dest_port
                                )
                                if verdict == "block":
                                    # Send Block Page logic if needed, or resets
                                    break
                                
                                # Flush buffer
                                writer.write(msg_buffer)
                                await writer.drain()
                                msg_buffer = b""
                                # Reset parser for next request (keep alive)
                                # For simplicity in prototype: we don't reset perfectly for keep-alive pipelines
                                # We assuming one request per connection or simply stream subsequent ones
                                server_parser.__init__() 
                            else:
                                # Buffering...
                                pass
                        else:
                            # Buffering headers...
                            pass
                        
                        # Safety: If buffer too large (>10MB), Flush to avoid DOS
                        if len(msg_buffer) > 10 * 1024 * 1024:
                             writer.write(msg_buffer)
                             await writer.drain()
                             msg_buffer = b""

                    else:
                        writer.write(data)
                        await writer.drain()
            except Exception as e:
                pass
            finally:
                try: writer.close()
                except: pass

        await asyncio.gather(
            forward(client_r, server_w, client_parser, "outbound"),
            forward(server_r, client_w, server_parser, "inbound")
        )
