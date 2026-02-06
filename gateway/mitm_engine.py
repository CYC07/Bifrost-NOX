import asyncio
import socket
import struct
import ssl
import logging
from cert_utils import CertificateAuthority
from http_parser import HTTPParser

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
            return ip, port
        except:
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
        is_tls = False
        server_name = dest_ip
        
        try:
            peek_data = sock.recv(4096, socket.MSG_PEEK)
            if peek_data and peek_data[0] == 0x16:
                is_tls = True
                sni = self.extract_sni(peek_data)
                if sni: server_name = sni
        except:
            pass

        logger.info(f"CONN: {client_writer.get_extra_info('peername')} -> {dest_ip}:{dest_port} TLS={is_tls} Host={server_name}")

        if is_tls:
            await self.handle_https(client_reader, client_writer, dest_ip, dest_port, server_name)
        else:
            await self.handle_http(client_reader, client_writer, dest_ip, dest_port)

    async def handle_http(self, client_reader, client_writer, dest_ip, dest_port):
        try:
            server_reader, server_writer = await asyncio.open_connection(dest_ip, dest_port)
        except Exception as e:
            logger.error(f"Upstream HTTP error: {e}")
            client_writer.close()
            return
        await self.pipe(client_reader, client_writer, server_reader, server_writer, is_https=False)

    async def handle_https(self, client_reader, client_writer, dest_ip, dest_port, server_name):
        try:
            server_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            server_ctx.check_hostname = False
            server_ctx.verify_mode = ssl.CERT_NONE
            server_reader, server_writer = await asyncio.open_connection(dest_ip, dest_port, ssl=server_ctx, server_hostname=server_name)
        except:
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
            
            await self.pipe(reader_ssl, writer_ssl, server_reader, server_writer, is_https=True)
        except Exception as e:
            logger.error(f"TLS Upgrade Failed: {e}")
            client_writer.close()
            server_writer.close()

    async def pipe(self, client_r, client_w, server_r, server_w, is_https):
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
                                verdict = await self.inspector.inspect_full(parser.headers, parser.body, direction, is_https)
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
