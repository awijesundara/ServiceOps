"""ServiceOps live events: Server-Sent Events for browsers.

    python -m tools.events_server

One process holds every open browser stream with almost no CPU or memory
(asyncio, no thread per connection) and one PostgreSQL connection that
LISTENs on ``serviceops_events`` (see serviceops_core/realtime.py).

    GET /events/stream?watch=ticket:42&notifications=1   text/event-stream
    GET /healthz                                          200 while LISTEN is up

The service makes no authorisation decisions of its own. When a stream opens
it calls the web application's /events/auth with the browser's own cookie;
that answer (user, tenant, which watched records are visible) decides what
the stream receives, and it is asked again every few minutes so a signed-out
or disabled account loses its stream. Events carry ids only; the browser
fetches the details from the web application under its normal rules.

Environment: DATABASE_URL, EVENTS_PORT (8090), EVENTS_AUTH_URL
(http://127.0.0.1:8080/events/auth), EVENTS_MAX_CONNECTIONS (5000),
EVENTS_MAX_PER_USER (20), EVENTS_HEARTBEAT_SECONDS (25).
"""
import asyncio
import json
import logging
import os
import signal
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import psycopg

CHANNEL = "serviceops_events"
PORT = int(os.getenv("EVENTS_PORT", "8090"))
AUTH_URL = os.getenv("EVENTS_AUTH_URL", "http://127.0.0.1:8080/events/auth")
MAX_CONNECTIONS = int(os.getenv("EVENTS_MAX_CONNECTIONS", "5000"))
MAX_PER_USER = int(os.getenv("EVENTS_MAX_PER_USER", "20"))
HEARTBEAT = int(os.getenv("EVENTS_HEARTBEAT_SECONDS", "25"))
MAX_HEADER_BYTES = 16384
FORWARDED = ("cookie", "user-agent", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
             "cf-connecting-ip", "cf-access-jwt-assertion", "accept-language")

log = logging.getLogger("serviceops.events")


class Stream:
    def __init__(self, writer, user_id, tenant_id, watch, notifications, headers):
        self.writer, self.user_id, self.tenant_id = writer, user_id, tenant_id
        self.watch, self.notifications, self.headers = set(watch), notifications, headers
        self.queue = asyncio.Queue(maxsize=100)

    def offer(self, frame):
        try:
            self.queue.put_nowait(frame)
        except asyncio.QueueFull:
            pass  # a stalled client misses signals; its periodic check catches up


class Hub:
    def __init__(self):
        self.streams = set()
        self.listening = False

    def per_user(self, user_id):
        return sum(1 for stream in self.streams if stream.user_id == user_id)

    def dispatch(self, payload):
        try:
            event = json.loads(payload)
        except ValueError:
            return
        tenant = event.get("tenant")
        if event.get("type") == "notification":
            frame = sse("notification", {})
            for stream in self.streams:
                if stream.notifications and stream.tenant_id == tenant and stream.user_id == event.get("user"):
                    stream.offer(frame)
        elif event.get("type") == "ticket":
            key = f"ticket:{event.get('id')}"
            frame = sse("ticket", {"id": event.get("id"), "actor": event.get("actor")})
            # Work lists learn only that something changed, not which ticket
            # (the list may not show it), and whether it was their own change.
            list_frames = {own: sse("tickets", {"self": own}) for own in (True, False)}
            for stream in self.streams:
                if stream.tenant_id != tenant:
                    continue
                if key in stream.watch:
                    stream.offer(frame)
                if "tickets" in stream.watch:
                    stream.offer(list_frames[event.get("actor") == stream.user_id])
        elif event.get("type") == "watch":
            # Project pages: the key names a project or work item the stream
            # was authorised to watch; the frame says only that it changed.
            key = event.get("key")
            for stream in self.streams:
                if stream.tenant_id == tenant and key in stream.watch:
                    stream.offer(sse("changed", {"key": key, "self": event.get("actor") == stream.user_id}))

    def broadcast(self, frame):
        for stream in self.streams:
            stream.offer(frame)


def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n".encode()


def database_dsn():
    url = os.environ["DATABASE_URL"]
    return url.replace("postgresql+psycopg://", "postgresql://", 1).replace("postgresql+psycopg2://", "postgresql://", 1)


async def listen(hub):
    """One LISTEN connection; on reconnect tell every browser to resync,
    since signals sent while disconnected were lost."""
    delay = 1
    while True:
        try:
            async with await psycopg.AsyncConnection.connect(database_dsn(), autocommit=True) as conn:
                await conn.execute(f"LISTEN {CHANNEL}")
                if hub.listening is False and delay > 1:
                    hub.broadcast(sse("resync", {}))
                hub.listening, delay = True, 1
                log.info("Listening on %s", CHANNEL)
                async for notify in conn.notifies():
                    hub.dispatch(notify.payload)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            hub.listening = False
            log.warning("LISTEN connection lost (%s); retrying in %ss", type(error).__name__, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)


async def authorise(client, headers, query):
    params = {"watch": ",".join(query.get("watch", [""])[0].split(",")[:5])}
    forwarded = {name: value for name, value in headers.items() if name in FORWARDED}
    forwarded["accept"] = "application/json"
    try:
        response = await client.get(AUTH_URL, params=params, headers=forwarded)
    except httpx.HTTPError:
        return None
    if response.status_code != 200 or not response.headers.get("content-type", "").startswith("application/json"):
        return None
    return response.json()


async def read_request(reader):
    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    if len(raw) > MAX_HEADER_BYTES:
        raise ValueError("header too large")
    lines = raw.decode("latin-1").split("\r\n")
    method, target, _ = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return method, target, headers


async def respond(writer, status, body=b"", content_type="text/plain"):
    writer.write(f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
                 "Cache-Control: no-store\r\nConnection: close\r\n\r\n".encode() + body)
    await writer.drain()


async def handle(reader, writer, hub, client):
    stream = None
    try:
        try:
            method, target, headers = await read_request(reader)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            return
        url = urlsplit(target)
        if url.path == "/healthz":
            await respond(writer, "200 OK" if hub.listening else "503 Service Unavailable",
                          b"ok" if hub.listening else b"not listening")
            return
        if method != "GET" or url.path != "/events/stream":
            await respond(writer, "404 Not Found", b"not found")
            return
        if len(hub.streams) >= MAX_CONNECTIONS:
            await respond(writer, "503 Service Unavailable", b"busy")
            return
        query = parse_qs(url.query)
        identity = await authorise(client, headers, query)
        if not identity:
            await respond(writer, "401 Unauthorized", b"sign in")
            return
        if hub.per_user(identity["user_id"]) >= MAX_PER_USER:
            await respond(writer, "429 Too Many Requests", b"too many streams")
            return
        notifications = query.get("notifications", ["1"])[0] != "0"
        stream = Stream(writer, identity["user_id"], identity["tenant_id"], identity.get("watch", []),
                        notifications, headers)
        hub.streams.add(stream)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
                     b"X-Accel-Buffering: no\r\nConnection: keep-alive\r\n\r\nretry: 5000\n\n"
                     + sse("hello", {"user_id": stream.user_id, "watch": sorted(stream.watch)}))
        await writer.drain()
        recheck_at = time.monotonic() + int(identity.get("revalidate_seconds", 300))
        while True:
            try:
                frame = await asyncio.wait_for(stream.queue.get(), timeout=HEARTBEAT)
            except asyncio.TimeoutError:
                frame = b": ping\n\n"
            writer.write(frame)
            await writer.drain()
            if time.monotonic() >= recheck_at:
                again = await authorise(client, headers, query)
                if not again or again["user_id"] != stream.user_id:
                    writer.write(sse("signed-out", {}))
                    await writer.drain()
                    return
                stream.watch = set(again.get("watch", []))
                recheck_at = time.monotonic() + int(again.get("revalidate_seconds", 300))
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        if stream:
            hub.streams.discard(stream)
        try:
            writer.close()
        except Exception:
            pass


async def serve(stop, port=None, host="0.0.0.0", ready=None):
    """Run until `stop` is set. `ready` (optional) receives the bound port."""
    hub = Hub()
    async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:
        server = await asyncio.start_server(lambda r, w: handle(r, w, hub, client), host,
                                            PORT if port is None else port, limit=MAX_HEADER_BYTES)
        listener = asyncio.create_task(listen(hub))
        bound = server.sockets[0].getsockname()[1]
        log.info("Events service on port %s", bound)
        if ready is not None:
            ready(bound)
        async with server:
            await stop.wait()
            listener.cancel()
            for stream in list(hub.streams):
                stream.writer.close()


async def main():
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                        format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}')
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await serve(stop)


if __name__ == "__main__":
    asyncio.run(main())
