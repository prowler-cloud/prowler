import gzip
import tarfile
from contextlib import contextmanager
from json import loads
from typing import Optional

import requests
import zstandard
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger

# Manifest media types that wrap several per-architecture manifests (a "fat
# manifest") rather than a single scannable image.
_MANIFEST_LIST_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}

# Compressed size of a single layer, checked against the manifest-declared
# size before downloading, and re-checked against actual bytes received.
MAX_LAYER_DOWNLOAD_BYTES = 100 * 1024 * 1024
# Size of a single extracted file considered for scanning.
MAX_FILE_BYTES = 1 * 1024 * 1024
# Hard cap on the number of files scanned per image, across all its layers.
MAX_FILES_PER_IMAGE = 5000
# Hard cap on total decompressed bytes read per image, across all its layers.
MAX_TOTAL_BYTES_PER_IMAGE = 500 * 1024 * 1024
LAYER_DOWNLOAD_TIMEOUT_SECONDS = 30


class _LayerTooLargeError(Exception):
    """Raised when a streamed layer exceeds MAX_LAYER_DOWNLOAD_BYTES."""


class _ImageTooLargeError(Exception):
    """Raised when decompressed image streams exceed their shared budget."""


class _CappedLayerReader:
    """A minimal read-only file object that caps the bytes it will yield.

    Wraps a streaming HTTP body (urllib3's ``response.raw``) so ``tarfile`` can
    read a gzip/uncompressed layer incrementally while enforcing an upper bound
    on the compressed bytes consumed. A manifest that under-declares a layer's
    size (the declared size is pre-checked separately) cannot make this buffer
    an unbounded amount of untrusted data: once ``max_bytes`` is exceeded the
    read raises ``_LayerTooLargeError`` instead of continuing.
    """

    def __init__(self, raw, max_bytes: int):
        """Store the underlying raw stream and the remaining byte budget."""
        self._raw = raw
        self._remaining = max_bytes

    def read(self, size: int = -1) -> bytes:
        """Read up to ``size`` bytes, never exceeding the remaining budget.

        A negative/None ``size`` (``read all``) is treated as "read what's left
        of the budget, plus one" so a lying stream can never pull an unbounded
        amount into memory and an over-cap layer is still detected.
        """
        if size is None or size < 0:
            size = self._remaining + 1
        to_read = min(size, self._remaining + 1)
        chunk = self._raw.read(to_read)
        self._remaining -= len(chunk)
        if self._remaining < 0:
            raise _LayerTooLargeError()
        return chunk


class _DecompressedByteBudget:
    """Track every decompressed byte consumed across an image's tar streams."""

    def __init__(self, max_bytes: int):
        """Set the shared decompressed-byte allowance."""
        self.remaining = max_bytes

    def wrap(self, raw):
        """Return a reader that charges bytes consumed from ``raw``."""
        return _BudgetedReader(raw, self)


class _BudgetedReader:
    """Charge all stream reads against a shared decompressed-byte budget."""

    def __init__(self, raw, budget: _DecompressedByteBudget):
        self._raw = raw
        self._budget = budget

    def read(self, size: int = -1) -> bytes:
        """Read without allowing the shared budget to be exceeded."""
        if size is None or size < 0:
            size = self._budget.remaining + 1
        chunk = self._raw.read(min(size, self._budget.remaining + 1))
        self._budget.remaining -= len(chunk)
        if self._budget.remaining < 0:
            raise _ImageTooLargeError()
        return chunk


class ImageScanFile(BaseModel):
    """A single file extracted from an image layer for secret scanning."""

    path: str
    layer_digest: str
    content: str


class ImageScanData(BaseModel):
    """An image's scannable content: config env/history and layer files."""

    env: list[str] = []
    history: list[str] = []
    files: list[ImageScanFile] = []
    # True when part of the image was not scanned -- a layer/file exceeded a
    # configured size or count limit, or the config blob could not be
    # retrieved/parsed -- so a clean result can be reported as MANUAL
    # (coverage incomplete) rather than a false PASS.
    truncated: bool = False


class ImageInspector:
    """Bounded, opt-in extraction of an ECR image's scannable content.

    Given a boto3 ECR client and an image digest, resolves the image's
    manifest (handling multi-arch manifest lists and skipping attestation
    manifests) and returns its configuration (environment variables, build
    history) and every filesystem layer's file contents, subject to this
    module's size and count limits.

    This is deliberately isolated from the ECR service so a future check can
    reuse the bounded extraction without the service downloading and
    decompressing image layers by default: the service only pays this cost
    when a check explicitly drives the inspector.
    """

    def fetch_image_scan_data(
        self, client, registry_id, repository_name, image_digest
    ) -> Optional[ImageScanData]:
        """Resolve one image's manifest and return its scannable content.

        Downloads the config blob (environment variables, build history)
        and every filesystem layer's file contents, bounded by the module's
        size/count limits.

        Returns:
            An ImageScanData, or None if the manifest could not be resolved.
        """
        manifest, truncated = self._resolve_image_manifest(
            client, registry_id, repository_name, image_digest
        )
        if manifest is None:
            return None

        env = []
        history = []

        config_digest = (manifest.get("config") or {}).get("digest")
        if config_digest:
            config_bytes = self._download_layer(
                client,
                registry_id,
                repository_name,
                config_digest,
                max_bytes=MAX_FILE_BYTES,
            )
            if config_bytes is None:
                # The config blob (env vars, build history) could not be
                # retrieved. Empty env/history would be indistinguishable
                # from a clean config, so mark coverage incomplete instead
                # of risking a false PASS.
                truncated = True
            else:
                try:
                    config_json = loads(config_bytes)
                    env = config_json.get("config", {}).get("Env", []) or []
                    history = [
                        step.get("created_by", "")
                        for step in config_json.get("history", [])
                        if step.get("created_by")
                    ]
                except Exception as error:
                    logger.warning(
                        f"{repository_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                    truncated = True

        files = []
        decompressed_budget = _DecompressedByteBudget(MAX_TOTAL_BYTES_PER_IMAGE)
        for layer in manifest.get("layers", []):
            if len(files) >= MAX_FILES_PER_IMAGE or decompressed_budget.remaining <= 0:
                truncated = True
                break

            layer_digest = layer.get("digest")
            layer_size = layer.get("size", 0)
            if layer_size and layer_size > MAX_LAYER_DOWNLOAD_BYTES:
                truncated = True
                continue

            try:
                with self._open_layer_tar_stream(
                    client,
                    registry_id,
                    repository_name,
                    layer_digest,
                    layer.get("mediaType", ""),
                    decompressed_budget,
                ) as tar_stream:
                    if tar_stream is None:
                        truncated = True
                        continue
                    for member in tar_stream:
                        if len(files) >= MAX_FILES_PER_IMAGE:
                            truncated = True
                            break
                        if not member.isfile():
                            continue
                        base_name = member.name.rsplit("/", 1)[-1]
                        if base_name.startswith(".wh."):
                            # Whiteout marker: a deletion recorded by the union
                            # filesystem, not real file content.
                            continue
                        if member.size > MAX_FILE_BYTES:
                            truncated = True
                            continue
                        try:
                            content = (
                                tar_stream.extractfile(member).read().decode("latin-1")
                            )
                        except _LayerTooLargeError:
                            # Over-cap while reading this member: truncate the
                            # whole layer rather than silently skipping one file.
                            raise
                        except Exception:
                            continue
                        files.append(
                            ImageScanFile(
                                path=member.name,
                                layer_digest=layer_digest,
                                content=content,
                            )
                        )
            except _LayerTooLargeError:
                # The layer streamed more bytes than MAX_LAYER_DOWNLOAD_BYTES
                # (a manifest under-declaring its size); skip it and disclose
                # the partial coverage rather than buffer unbounded data.
                truncated = True
                continue
            except _ImageTooLargeError:
                truncated = True
                break

        return ImageScanData(env=env, history=history, files=files, truncated=truncated)

    def _resolve_image_manifest(
        self, client, registry_id, repository_name, image_digest
    ) -> tuple[Optional[dict], bool]:
        """Resolve an image digest to a single scannable image manifest.

        Multi-arch images are stored as a manifest list/image index pointing
        at one manifest per platform (plus, often, an attestation manifest
        that isn't a real image). This picks one real platform manifest to
        scan; the other architectures in the same list are not scanned.
        """
        try:
            manifest, media_type = self._batch_get_manifest(
                client, registry_id, repository_name, image_digest
            )
            if manifest is None:
                return None, False

            truncated = False
            if media_type in _MANIFEST_LIST_MEDIA_TYPES:
                truncated = True
                child_digest = self._select_child_manifest_digest(manifest)
                if not child_digest:
                    return None, truncated
                manifest, _ = self._batch_get_manifest(
                    client, registry_id, repository_name, child_digest
                )
            if manifest is not None and not (
                manifest.get("config") or manifest.get("layers")
            ):
                # A resolved manifest with neither a config nor layers has
                # nothing to scan (e.g. a nested manifest list, or an
                # unsupported manifest shape) -- treat it as unresolvable so
                # the caller reports MANUAL instead of a false PASS.
                return None, truncated
            return manifest, truncated
        except Exception as error:
            logger.error(
                f"{client.meta.region_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None, False

    @staticmethod
    def _batch_get_manifest(client, registry_id, repository_name, image_digest):
        """Fetch and parse the raw manifest JSON for a single image digest.

        Returns:
            A (manifest, media_type) tuple, or (None, None) if not found.
        """
        response = client.batch_get_image(
            registryId=registry_id,
            repositoryName=repository_name,
            imageIds=[{"imageDigest": image_digest}],
        )
        images = response.get("images", [])
        if not images:
            return None, None
        manifest = loads(images[0]["imageManifest"])
        media_type = manifest.get("mediaType") or images[0].get(
            "imageManifestMediaType"
        )
        return manifest, media_type

    @staticmethod
    def _select_child_manifest_digest(manifest_list: dict) -> Optional[str]:
        """Pick one real platform manifest's digest from a manifest list.

        Prefers linux/amd64, falling back to the first remaining candidate
        once attestation manifests (platform "unknown/unknown", or
        annotated as an attestation manifest) are excluded.

        Returns:
            The chosen manifest's digest, or None if no candidate remains.
        """
        candidates = []
        for entry in manifest_list.get("manifests", []):
            platform = entry.get("platform", {}) or {}
            annotations = entry.get("annotations", {}) or {}
            if (
                platform.get("architecture") == "unknown"
                or platform.get("os") == "unknown"
            ):
                # Attestation manifests (SBOMs, provenance, signatures) are
                # attached to the index as "unknown/unknown" platform entries.
                continue
            if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
                continue
            candidates.append(entry)

        for entry in candidates:
            platform = entry.get("platform", {}) or {}
            if (
                platform.get("architecture") == "amd64"
                and platform.get("os") == "linux"
            ):
                return entry.get("digest")

        return candidates[0].get("digest") if candidates else None

    @staticmethod
    def _get_layer_download_url(
        client, registry_id, repository_name, layer_digest
    ) -> Optional[str]:
        """Resolve the presigned download URL for one layer or config blob.

        Returns:
            The presigned URL, or None if ECR did not return one.
        """
        response = client.get_download_url_for_layer(
            registryId=registry_id,
            repositoryName=repository_name,
            layerDigest=layer_digest,
        )
        return response.get("downloadUrl")

    @staticmethod
    def _download_layer(
        client, registry_id, repository_name, layer_digest, max_bytes=None
    ) -> Optional[bytes]:
        """Download one layer or config blob via its presigned URL.

        Streams the response, aborting once `max_bytes` is exceeded, so a
        lying or oversized blob is never buffered in full. Used for the config
        blob and for zstd layers (which cannot be streamed into tarfile);
        gzip/uncompressed layers are streamed by `_open_layer_tar_stream`.

        Returns:
            The blob's bytes, or None if it could not be downloaded or
            exceeded `max_bytes`.
        """
        try:
            download_url = ImageInspector._get_layer_download_url(
                client, registry_id, repository_name, layer_digest
            )
            if not download_url:
                return None

            downloaded = bytearray()
            with requests.get(
                download_url,
                stream=True,
                timeout=LAYER_DOWNLOAD_TIMEOUT_SECONDS,
                allow_redirects=False,
            ) as http_response:
                http_response.raise_for_status()
                for chunk in http_response.iter_content(chunk_size=1024 * 1024):
                    downloaded.extend(chunk)
                    if max_bytes and len(downloaded) > max_bytes:
                        return None
            return bytes(downloaded)
        except Exception as error:
            logger.warning(
                f"{repository_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    @contextmanager
    def _open_layer_tar_stream(
        self,
        client,
        registry_id,
        repository_name,
        layer_digest,
        media_type: str,
        decompressed_budget: _DecompressedByteBudget,
    ):
        """Yield an open TarFile for one layer, streamed from the download.

        gzip, zstd, and uncompressed tar layers are all streamed straight from
        the download into `tarfile` (streaming mode reads a file-like object
        sequentially), so neither the compressed blob nor a decompressed copy is
        ever buffered in full. A `_CappedLayerReader` enforces
        `MAX_LAYER_DOWNLOAD_BYTES` on the compressed bytes (guarding a manifest
        that under-declares the layer size); zstd is decompressed incrementally
        via `zstandard`'s streaming reader, so a crafted frame can no longer
        expand unbounded in memory, and the decompressed side is bounded by the
        caller's per-image budget as it iterates members.

        Yields:
            An open TarFile, or None for an unrecognized media type or a
            download/decompression failure. Raises `_LayerTooLargeError` if a
            streamed layer's compressed bytes exceed `MAX_LAYER_DOWNLOAD_BYTES`.
        """
        if media_type.endswith("gzip"):
            decompress = "gzip"
        elif media_type.endswith("zstd"):
            decompress = "zstd"
        elif media_type.endswith("tar"):
            decompress = None
        else:
            yield None
            return

        # Only the setup (URL resolution, connection, tar-header parse) is
        # guarded here; a failure yields None. The `yield tar_stream` below is
        # kept out of this try so exceptions raised while the caller iterates
        # members (e.g. _LayerTooLargeError) propagate instead of triggering a
        # forbidden second yield.
        try:
            download_url = ImageInspector._get_layer_download_url(
                client, registry_id, repository_name, layer_digest
            )
            if not download_url:
                yield None
                return
            http_response = requests.get(
                download_url,
                stream=True,
                timeout=LAYER_DOWNLOAD_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
            try:
                http_response.raise_for_status()
                # Cap the compressed bytes read from the network; for zstd,
                # decompress that capped stream incrementally so the decompressed
                # data is never materialized in full.
                source = _CappedLayerReader(http_response.raw, MAX_LAYER_DOWNLOAD_BYTES)
                if decompress == "gzip":
                    source = gzip.GzipFile(fileobj=source)
                elif decompress == "zstd":
                    source = zstandard.ZstdDecompressor().stream_reader(source)
                source = decompressed_budget.wrap(source)
                tar_stream = tarfile.open(fileobj=source, mode="r|")
            except (_LayerTooLargeError, _ImageTooLargeError):
                http_response.close()
                raise
            except Exception:
                http_response.close()
                raise
        except Exception as error:
            logger.warning(
                f"{repository_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            yield None
            return

        with http_response, tar_stream:
            yield tar_stream
