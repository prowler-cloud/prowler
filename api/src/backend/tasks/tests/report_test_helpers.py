import io
import struct
import zlib
from types import ModuleType, SimpleNamespace
from typing import Any

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    checksum = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)
    )


def _build_tiny_png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    # Filter byte 0 plus one white RGB pixel.
    idat = zlib.compress(b"\x00\xff\xff\xff")
    return (
        PNG_SIGNATURE
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


_TINY_PNG_BYTES = _build_tiny_png()


def fake_png_buffer() -> io.BytesIO:
    return io.BytesIO(_TINY_PNG_BYTES)


def patch_chart_helpers(
    monkeypatch: Any, module: ModuleType, names: tuple[str, ...]
) -> dict[str, list[dict[str, Any]]]:
    calls: dict[str, list[dict[str, Any]]] = {name: [] for name in names}

    def _build_fake_chart(name: str):
        def _fake_chart(*args: Any, **kwargs: Any) -> io.BytesIO:
            calls[name].append({"args": args, "kwargs": kwargs})
            return fake_png_buffer()

        return _fake_chart

    for name in names:
        monkeypatch.setattr(module, name, _build_fake_chart(name))

    return calls


def patch_report_gc(monkeypatch: Any) -> None:
    from tasks.jobs import report as report_module
    from tasks.jobs.reports import base as base_report_module
    from tasks.jobs.reports import threatscore as threatscore_report_module

    gc_stub = SimpleNamespace(collect=lambda: 0)
    monkeypatch.setattr(report_module, "gc", gc_stub)
    monkeypatch.setattr(base_report_module, "gc", gc_stub)
    monkeypatch.setattr(threatscore_report_module, "gc", gc_stub)
