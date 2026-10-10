"""Minimal HTTP/2 prior-knowledge (h2c) research transport using hyper-h2.

Real HTTP/2 frames are exchanged over loopback in the testbed. This is NOT a
3GPP SBI implementation, and cleartext h2c is LAB ONLY (no mutual TLS/OAuth).
"""
from __future__ import annotations
import asyncio
import json
from urllib.parse import urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class H2Server:
    def __init__(self, handler):
        self.handler = handler
        self.server = None
        self.port = None

    async def start(self, port=0):
        self.server = await asyncio.start_server(self._connection, "127.0.0.1", port)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def close(self):
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _connection(self, reader, writer):
        h = H2Connection(H2Configuration(client_side=False, header_encoding="utf-8"))
        h.initiate_connection()
        writer.write(h.data_to_send())
        reqs = {}
        try:
            while not reader.at_eof():
                chunk = await asyncio.wait_for(reader.read(65535), timeout=8)
                if not chunk:
                    break
                events = h.receive_data(chunk)
                for event in events:
                    if isinstance(event, RequestReceived):
                        reqs[event.stream_id] = {"headers": dict(event.headers), "body": bytearray()}
                    elif isinstance(event, DataReceived):
                        if event.stream_id in reqs:
                            reqs[event.stream_id]["body"].extend(event.data)
                        h.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded) and event.stream_id in reqs:
                        req = reqs.pop(event.stream_id)
                        try:
                            result = self.handler(req["headers"], bytes(req["body"]))
                            if asyncio.iscoroutine(result):
                                result = await result
                            status, payload = result
                        except Exception as e:
                            status, payload = 500, {"error": type(e).__name__}
                        body = encode(payload)
                        h.send_headers(event.stream_id, [(":status", str(status)),
                                    ("content-type", "application/json")])
                        h.send_data(event.stream_id, body, end_stream=True)
                writer.write(h.data_to_send())
                await writer.drain()
        except (ConnectionError, OSError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def h2_request(url: str, path: str, method="GET", body=None, timeout=8):
    """Return (status, json body, count of sent app+h2 bytes, response headers).

    h2c prior-knowledge is the protocol used by plain HTTP/2 SBI in the lab.
    """
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError("Research client supports HTTP/2 h2c only")
    port = parts.port or 80

    async def once():
        reader, writer = await asyncio.open_connection(parts.hostname, port)
        h = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
        total_sent = 0
        total_received = 0
        try:
            h.initiate_connection()
            headers = [(":method", method), (":scheme", "http"),
                       (":authority", parts.netloc), (":path", path),
                       ("accept", "application/json")]
            if body is not None:
                headers.append(("content-type", "application/json"))
            stream = h.get_next_available_stream_id()
            h.send_headers(stream, headers, end_stream=body is None)
            if body is not None:
                h.send_data(stream, encode(body), end_stream=True)
            outbound = h.data_to_send()
            total_sent += len(outbound)
            writer.write(outbound)
            await writer.drain()
            output = bytearray()
            code = None
            out_headers = {}
            while True:
                data = await reader.read(65535)
                if not data:
                    raise ConnectionError("HTTP/2 connection closed before response completed")
                total_received += len(data)
                for event in h.receive_data(data):
                    if isinstance(event, ResponseReceived) and event.stream_id == stream:
                        out_headers = dict(event.headers)
                        code = int(out_headers[":status"])
                    elif isinstance(event, DataReceived):
                        if event.stream_id == stream:
                            output.extend(event.data)
                        h.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded) and event.stream_id == stream:
                        return code, json.loads(output) if output else {}, total_sent + total_received, out_headers
                outbound = h.data_to_send()
                total_sent += len(outbound)
                writer.write(outbound)
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
    return await asyncio.wait_for(once(), timeout)
