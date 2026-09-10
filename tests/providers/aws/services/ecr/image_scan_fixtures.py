"""Shared fixtures for ECR image-scanning tests.

Used by both the ECR service tests (orchestration) and the image_inspection
tests (bounded extraction), so the manifest/layer fixtures and the fake layer
download live in one place. moto implements neither BatchGetImage nor
GetDownloadUrlForLayer, so each test registers the manifests/blobs it needs in
``MANIFESTS_BY_DIGEST``/``BLOBS_BY_DIGEST`` and a patched ``_make_api_call``
serves them.
"""

import io
import tarfile

IMAGE_DIGEST = f"sha256:{'1' * 64}"
CONFIG_DIGEST = f"sha256:{'c' * 64}"
LAYER_DIGEST = f"sha256:{'d' * 64}"
MULTI_ARCH_INDEX_DIGEST = f"sha256:{'2' * 64}"
CHILD_AMD64_DIGEST = f"sha256:{'3' * 64}"
CHILD_ARM64_DIGEST = f"sha256:{'4' * 64}"
ATTESTATION_DIGEST = f"sha256:{'5' * 64}"

SIMPLE_MANIFEST = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {
        "mediaType": "application/vnd.docker.container.image.v1+json",
        "digest": CONFIG_DIGEST,
        "size": 100,
    },
    "layers": [
        {
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "digest": LAYER_DIGEST,
            "size": 200,
        }
    ],
}

MULTI_ARCH_MANIFEST_LIST = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
    "manifests": [
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": CHILD_AMD64_DIGEST,
            "size": 10,
            "platform": {"architecture": "amd64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": CHILD_ARM64_DIGEST,
            "size": 10,
            "platform": {"architecture": "arm64", "os": "linux"},
        },
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": ATTESTATION_DIGEST,
            "size": 10,
            "platform": {"architecture": "unknown", "os": "unknown"},
            "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
        },
    ],
}

CONFIG_JSON = {
    "config": {"Env": ["PATH=/usr/bin", "TOKEN=super-secret-value"]},
    "history": [
        {"created_by": "/bin/sh -c #(nop) ADD file"},
        {"created_by": "RUN echo hi"},
    ],
}

# Per-test fixtures keyed by digest. moto implements neither BatchGetImage nor
# GetDownloadUrlForLayer, so tests populate these and a patched _make_api_call /
# requests.get serves them. Cleared between tests via reset_image_fixtures().
MANIFESTS_BY_DIGEST = {}
BLOBS_BY_DIGEST = {}


def reset_image_fixtures():
    """Clear the per-test manifest/blob fixtures."""
    MANIFESTS_BY_DIGEST.clear()
    BLOBS_BY_DIGEST.clear()


def build_tar(files: dict) -> bytes:
    """Build an uncompressed tar archive from the given files."""
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        for name, content in files.items():
            data = content.encode("latin-1")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return tar_buffer.getvalue()


def build_gzip_tar(files: dict) -> bytes:
    """Build a gzip-compressed tar archive from the given files."""
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode("latin-1")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return tar_buffer.getvalue()


class FakeLayerResponse:
    """A minimal stand-in for a requests.Response over a layer download."""

    def __init__(self, data: bytes):
        """Store the fixture bytes to serve (via iter_content and .raw)."""
        self._data = data
        # Streaming gzip/tar layers read the compressed bytes straight from
        # response.raw; the buffered config/zstd path uses iter_content.
        self.raw = io.BytesIO(data)

    def raise_for_status(self):
        """No-op: fixture responses are always successful."""

    def iter_content(self, chunk_size=1024 * 1024):
        """Yield the fixture bytes in chunks."""
        for start in range(0, len(self._data), chunk_size):
            yield self._data[start : start + chunk_size]

    def close(self):
        """Close the backing raw stream, mirroring requests.Response.close."""
        self.raw.close()

    def __enter__(self):
        """Support use as a context manager."""
        return self

    def __exit__(self, *_):
        """Close on exit, mirroring requests.Response context-manager use."""
        self.close()
        return False


def mock_requests_get(url, **_):
    """Return the fixture bytes registered for the requested layer's URL."""
    digest = url.rsplit("/", 1)[-1]
    return FakeLayerResponse(BLOBS_BY_DIGEST[digest])
