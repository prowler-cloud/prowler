"""Server-Sent Events (SSE) configuration.

Wires django-eventstream into the platform: Valkey Pub/Sub backend on a
dedicated DB (separate from the Celery broker), the platform channel
manager, and headers that match the existing CORS allowlist.
"""

from config.env import env
from config.settings.celery import (
    VALKEY_HOST,
    VALKEY_PASSWORD,
    VALKEY_PORT,
    VALKEY_SCHEME,
    VALKEY_USERNAME,
)

# Dedicated Valkey DB for the SSE Pub/Sub bus. Kept distinct from the
# Celery broker DB so a noisy broker can't shoulder out streaming
# traffic on the same keyspace.
EVENTSTREAM_VALKEY_DB = env.int("EVENTSTREAM_VALKEY_DB", default=2)

EVENTSTREAM_REDIS: dict = {
    "host": VALKEY_HOST,
    "port": int(VALKEY_PORT),
    "db": EVENTSTREAM_VALKEY_DB,
}
if VALKEY_PASSWORD:
    EVENTSTREAM_REDIS["password"] = VALKEY_PASSWORD
if VALKEY_USERNAME:
    EVENTSTREAM_REDIS["username"] = VALKEY_USERNAME
if VALKEY_SCHEME == "rediss":
    EVENTSTREAM_REDIS["ssl"] = True

# Platform channel manager — performs the per-feature authorization and
# rewrites the placeholder channel from the URL into the canonical
# tenant-scoped channel name. See ``api.sse.channelmanager``.
EVENTSTREAM_CHANNELMANAGER_CLASS = "api.sse.channelmanager.SSEChannelManager"

# Headers a browser EventSource may legitimately send. Keep tight; the
# stream itself reads no body, so no permissive defaults.
EVENTSTREAM_ALLOW_HEADERS = "Cache-Control, Last-Event-ID"
