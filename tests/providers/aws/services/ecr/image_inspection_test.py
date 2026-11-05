import gzip
import json
import random
import tarfile
from io import BytesIO
from unittest.mock import patch

import botocore
import pytest
import zstandard
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.ecr.image_inspection import (
    MAX_FILE_BYTES,
    MAX_LAYER_DOWNLOAD_BYTES,
    ImageInspector,
    _CappedLayerReader,
    _LayerTooLargeError,
)
from tests.providers.aws.services.ecr.image_scan_fixtures import (
    BLOBS_BY_DIGEST,
    CHILD_AMD64_DIGEST,
    CHILD_ARM64_DIGEST,
    CONFIG_DIGEST,
    CONFIG_JSON,
    IMAGE_DIGEST,
    LAYER_DIGEST,
    MANIFESTS_BY_DIGEST,
    MULTI_ARCH_INDEX_DIGEST,
    MULTI_ARCH_MANIFEST_LIST,
    SIMPLE_MANIFEST,
    build_gzip_tar,
    build_tar,
    mock_requests_get,
    reset_image_fixtures,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

REPO_NAME = "test-repo"

_original_make_api_call = botocore.client.BaseClient._make_api_call

_REQUESTS_GET = "prowler.providers.aws.services.ecr.image_inspection.requests.get"


def mock_make_api_call(self, operation_name, kwarg):
    """Serve BatchGetImage/GetDownloadUrlForLayer from fixtures; delegate the rest.

    moto implements neither operation, so they are answered from the per-test
    ``MANIFESTS_BY_DIGEST`` fixtures; every other call falls through to the real
    (moto-backed) implementation.
    """
    if operation_name == "BatchGetImage":
        digest = kwarg["imageIds"][0]["imageDigest"]
        manifest = MANIFESTS_BY_DIGEST.get(digest)
        if manifest is None:
            return {
                "images": [],
                "failures": [
                    {
                        "imageId": {"imageDigest": digest},
                        "failureCode": "ImageNotFound",
                    }
                ],
            }
        return {
            "images": [
                {
                    "imageManifest": json.dumps(manifest),
                    "imageManifestMediaType": manifest.get("mediaType", ""),
                }
            ]
        }
    if operation_name == "GetDownloadUrlForLayer":
        digest = kwarg["layerDigest"]
        return {"downloadUrl": f"https://layers.example.com/{digest}"}
    return _original_make_api_call(self, operation_name, kwarg)


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_ImageInspector:
    """Tests for the bounded image-content extraction in image_inspection."""

    @pytest.fixture(autouse=True)
    def _reset_image_fixtures(self):
        """Isolate the BatchGetImage/GetDownloadUrlForLayer fixtures per test."""
        reset_image_fixtures()
        yield
        reset_image_fixtures()

    @staticmethod
    def _fetch(digest=IMAGE_DIGEST):
        """Fetch scan data for one image, with the layer download stubbed."""
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        with patch(_REQUESTS_GET, new=mock_requests_get):
            return ImageInspector().fetch_image_scan_data(
                ecr_client, AWS_ACCOUNT_NUMBER, REPO_NAME, digest
            )

    @mock_aws
    def test_fetch_image_scan_data_simple_image(self):
        """A single-manifest image's config and layer file are scanned."""
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = SIMPLE_MANIFEST
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        BLOBS_BY_DIGEST[LAYER_DIGEST] = build_gzip_tar({"app/config.py": "TOKEN = 'x'"})

        scan_data = self._fetch()

        assert scan_data is not None
        assert scan_data.env == ["PATH=/usr/bin", "TOKEN=super-secret-value"]
        assert scan_data.history == ["/bin/sh -c #(nop) ADD file", "RUN echo hi"]
        assert len(scan_data.files) == 1
        assert scan_data.files[0].path == "app/config.py"
        assert scan_data.files[0].layer_digest == LAYER_DIGEST
        assert scan_data.files[0].content == "TOKEN = 'x'"
        assert scan_data.truncated is False

    @mock_aws
    def test_fetch_image_scan_data_resolves_multi_arch_manifest(self):
        """A multi-arch scan is incomplete when only one child is inspected."""
        MANIFESTS_BY_DIGEST[MULTI_ARCH_INDEX_DIGEST] = MULTI_ARCH_MANIFEST_LIST
        MANIFESTS_BY_DIGEST[CHILD_AMD64_DIGEST] = SIMPLE_MANIFEST
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        BLOBS_BY_DIGEST[LAYER_DIGEST] = build_gzip_tar({"app/config.py": "TOKEN = 'x'"})

        scan_data = self._fetch(digest=MULTI_ARCH_INDEX_DIGEST)

        # Only the amd64/linux child manifest is resolved and scanned; the
        # arm64 and attestation entries in the manifest list are ignored.
        assert scan_data is not None
        assert scan_data.env == ["PATH=/usr/bin", "TOKEN=super-secret-value"]
        assert len(scan_data.files) == 1
        assert scan_data.files[0].path == "app/config.py"
        assert scan_data.truncated is True

    @mock_aws
    def test_fetch_image_scan_data_skips_oversized_layer(self):
        """A layer over the size cap is skipped, not downloaded."""
        oversized_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": CONFIG_DIGEST, "size": 10},
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": LAYER_DIGEST,
                    "size": MAX_LAYER_DOWNLOAD_BYTES + 1,
                }
            ],
        }
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = oversized_manifest
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()

        scan_data = self._fetch()

        # The oversized layer is never downloaded (only the config blob is in
        # BLOBS_BY_DIGEST), yet the fetch completes without raising.
        assert scan_data is not None
        assert scan_data.files == []
        assert scan_data.truncated is True

    @mock_aws
    def test_fetch_image_scan_data_manifest_not_found_returns_none(self):
        """An unknown digest resolves to no scan data."""
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)

        scan_data = ImageInspector().fetch_image_scan_data(
            ecr_client, AWS_ACCOUNT_NUMBER, REPO_NAME, f"sha256:{'f' * 64}"
        )

        assert scan_data is None

    @mock_aws
    def test_fetch_image_scan_data_config_download_failure_marks_truncated(self):
        """A config blob that cannot be retrieved marks coverage incomplete.

        Empty env/history would otherwise be indistinguishable from a clean
        config, so the fetch flags the result as truncated rather than risking
        a false PASS at the check level.
        """
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = SIMPLE_MANIFEST
        # Register the layer but NOT the config blob, so the config download
        # fails while the layer is still scanned cleanly.
        BLOBS_BY_DIGEST[LAYER_DIGEST] = build_gzip_tar({"app/config.py": "clean"})

        scan_data = self._fetch()

        assert scan_data is not None
        assert scan_data.env == []
        assert scan_data.history == []
        assert scan_data.truncated is True
        assert [f.path for f in scan_data.files] == ["app/config.py"]

    @mock_aws
    def test_fetch_image_scan_data_member_over_remaining_budget_is_truncated(self):
        """A layer exceeding the remaining stream budget is truncated.

        Tar headers and padding consume the authoritative decompressed-byte
        budget before member payloads are exposed for scanning.
        """
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = SIMPLE_MANIFEST
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        BLOBS_BY_DIGEST[LAYER_DIGEST] = build_gzip_tar(
            {"app/first.txt": "a" * 100, "app/second.txt": "b" * 5000}
        )

        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        with (
            patch(_REQUESTS_GET, new=mock_requests_get),
            patch(
                "prowler.providers.aws.services.ecr.image_inspection.MAX_TOTAL_BYTES_PER_IMAGE",
                1000,
            ),
        ):
            scan_data = ImageInspector().fetch_image_scan_data(
                ecr_client, AWS_ACCOUNT_NUMBER, REPO_NAME, IMAGE_DIGEST
            )

        assert scan_data is not None
        assert scan_data.files == []
        assert scan_data.truncated is True

    @mock_aws
    def test_fetch_image_scan_data_oversized_members_count_toward_budget(self):
        """Members skipped for size still count toward the per-image budget.

        A streaming reader must decompress each member to advance past it, so
        oversized-and-skipped members must still consume budget; otherwise a
        layer of many just-over-limit files would decompress unbounded. The
        loop must stop before reaching a later scannable member.
        """
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = SIMPLE_MANIFEST
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        # Ten 300-byte members (each over the patched 100-byte MAX_FILE_BYTES,
        # so each is skipped for content) followed by a small, scannable file.
        layer = {f"app/big{i}.bin": "x" * 300 for i in range(10)}
        layer["app/reachable.txt"] = "hello"
        BLOBS_BY_DIGEST[LAYER_DIGEST] = build_gzip_tar(layer)

        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        with (
            patch(_REQUESTS_GET, new=mock_requests_get),
            patch(
                "prowler.providers.aws.services.ecr.image_inspection.MAX_FILE_BYTES",
                100,
            ),
            patch(
                "prowler.providers.aws.services.ecr.image_inspection.MAX_TOTAL_BYTES_PER_IMAGE",
                1000,
            ),
        ):
            scan_data = ImageInspector().fetch_image_scan_data(
                ecr_client, AWS_ACCOUNT_NUMBER, REPO_NAME, IMAGE_DIGEST
            )

        assert scan_data is not None
        # The oversized members exhaust the 1000-byte budget after ~3 of them,
        # so the loop stops before ever reaching app/reachable.txt. If skipped
        # members were not counted, reachable.txt would be scanned.
        assert scan_data.files == []
        assert scan_data.truncated is True

    @mock_aws
    def test_fetch_image_scan_data_tar_over_stream_budget_is_truncated(self):
        """Tar headers, padding, and non-files consume the image byte budget."""
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = SIMPLE_MANIFEST
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        layer = BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as archive:
            for index in range(20):
                directory = tarfile.TarInfo(f"metadata-{index}/")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
            content = b"x"
            member = tarfile.TarInfo("app/reachable.txt")
            member.size = len(content)
            archive.addfile(member, BytesIO(content))
        BLOBS_BY_DIGEST[LAYER_DIGEST] = gzip.compress(layer.getvalue())

        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        with (
            patch(_REQUESTS_GET, new=mock_requests_get),
            patch(
                "prowler.providers.aws.services.ecr.image_inspection.MAX_TOTAL_BYTES_PER_IMAGE",
                10 * 1024 - 1,
            ),
        ):
            scan_data = ImageInspector().fetch_image_scan_data(
                ecr_client, AWS_ACCOUNT_NUMBER, REPO_NAME, IMAGE_DIGEST
            )

        assert scan_data is not None
        assert scan_data.files == []
        assert scan_data.truncated is True

    def test_select_child_manifest_digest_falls_back_to_non_amd64(self):
        """With no amd64/linux entry, the first non-attestation candidate is picked."""
        manifest_list = {
            "manifests": [
                {
                    "digest": CHILD_ARM64_DIGEST,
                    "platform": {"architecture": "arm64", "os": "linux"},
                },
                {
                    "digest": f"sha256:{'5' * 64}",
                    "platform": {"architecture": "unknown", "os": "unknown"},
                    "annotations": {
                        "vnd.docker.reference.type": "attestation-manifest"
                    },
                },
            ]
        }

        digest = ImageInspector._select_child_manifest_digest(manifest_list)

        assert digest == CHILD_ARM64_DIGEST

    @mock_aws
    def test_fetch_image_scan_data_zstd_layer(self):
        """A zstd-compressed layer is streamed, decompressed, and scanned."""
        zstd_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": CONFIG_DIGEST, "size": 100},
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
                    "digest": LAYER_DIGEST,
                    "size": 200,
                }
            ],
        }
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = zstd_manifest
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        BLOBS_BY_DIGEST[LAYER_DIGEST] = zstandard.ZstdCompressor().compress(
            build_tar({"app/config.py": "TOKEN = 'x'"})
        )

        scan_data = self._fetch()

        assert scan_data is not None
        assert len(scan_data.files) == 1
        assert scan_data.files[0].content == "TOKEN = 'x'"

    @mock_aws
    def test_fetch_image_scan_data_zstd_layer_over_compressed_cap_is_truncated(self):
        """A zstd layer whose compressed bytes exceed the cap is truncated.

        The streaming decompressor reads through a _CappedLayerReader, so a
        layer whose compressed size exceeds MAX_LAYER_DOWNLOAD_BYTES (patched
        here) is cut off and disclosed via truncated instead of being buffered
        or decompressed unbounded.
        """
        zstd_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": CONFIG_DIGEST, "size": 100},
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+zstd",
                    "digest": LAYER_DIGEST,
                    # Declares zero size so it passes the pre-download check;
                    # the actual compressed bytes exceed the (patched) cap.
                    "size": 0,
                }
            ],
        }
        # Incompressible payload (so the compressed frame stays large), split
        # across two members so the first is read before the cap trips while
        # the second is streamed.
        rng = random.Random(0)
        incompressible = bytes(rng.randrange(256) for _ in range(64 * 1024)).decode(
            "latin-1"
        )
        layer_blob = zstandard.ZstdCompressor().compress(
            build_tar({"app/config.py": "TOKEN = 'x'", "app/big.bin": incompressible})
        )
        assert len(layer_blob) > 10 * 1024
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = zstd_manifest
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        BLOBS_BY_DIGEST[LAYER_DIGEST] = layer_blob

        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        with (
            patch(_REQUESTS_GET, new=mock_requests_get),
            patch(
                "prowler.providers.aws.services.ecr.image_inspection.MAX_LAYER_DOWNLOAD_BYTES",
                len(layer_blob) - 1,
            ),
        ):
            scan_data = ImageInspector().fetch_image_scan_data(
                ecr_client, AWS_ACCOUNT_NUMBER, REPO_NAME, IMAGE_DIGEST
            )

        assert scan_data is not None
        assert scan_data.truncated is True

    @mock_aws
    def test_fetch_image_scan_data_uncompressed_tar_layer(self):
        """An uncompressed tar layer is read and scanned directly."""
        tar_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": CONFIG_DIGEST, "size": 100},
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": LAYER_DIGEST,
                    "size": 200,
                }
            ],
        }
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = tar_manifest
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        BLOBS_BY_DIGEST[LAYER_DIGEST] = build_tar({"app/config.py": "TOKEN = 'x'"})

        scan_data = self._fetch()

        assert scan_data is not None
        assert len(scan_data.files) == 1
        assert scan_data.files[0].content == "TOKEN = 'x'"

    @mock_aws
    def test_fetch_image_scan_data_skips_whiteout_and_oversized_file(self):
        """Whiteout markers and oversized files are skipped, not scanned."""
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = SIMPLE_MANIFEST
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        BLOBS_BY_DIGEST[LAYER_DIGEST] = build_gzip_tar(
            {
                ".wh.deleted": "should never appear",
                "app/config.py": "TOKEN = 'x'",
                "app/oversized.bin": "x" * (MAX_FILE_BYTES + 1),
            }
        )

        scan_data = self._fetch()

        assert scan_data is not None
        assert [f.path for f in scan_data.files] == ["app/config.py"]
        assert scan_data.truncated is True

    def test_capped_layer_reader_allows_up_to_max(self):
        """Reading exactly the byte budget succeeds and then reports EOF."""
        import io

        reader = _CappedLayerReader(io.BytesIO(b"x" * 10), max_bytes=10)
        assert reader.read() == b"x" * 10
        assert reader.read() == b""

    def test_capped_layer_reader_raises_when_exceeding_max(self):
        """A stream longer than the byte budget raises _LayerTooLargeError."""
        import io

        reader = _CappedLayerReader(io.BytesIO(b"x" * 100), max_bytes=10)
        with pytest.raises(_LayerTooLargeError):
            reader.read()

    @mock_aws
    def test_fetch_image_scan_data_streamed_layer_over_cap_is_truncated(self):
        """A layer streaming past MAX_LAYER_DOWNLOAD_BYTES is skipped, not buffered."""
        undersized_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": CONFIG_DIGEST, "size": 100},
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": LAYER_DIGEST,
                    # Declares zero size so it passes the pre-download check;
                    # the actual streamed bytes exceed the (patched) cap.
                    "size": 0,
                }
            ],
        }
        # Two-member layer: a small first file that is scanned, then a large
        # incompressible second file. The blob must exceed tarfile's internal
        # read buffer (~10 KB) so tarfile.open() consumes only part of it and
        # the cap (set one byte below the full layer) is instead exceeded while
        # the second member's content is read during archive iteration.
        rng = random.Random(0)
        incompressible = bytes(rng.randrange(256) for _ in range(64 * 1024)).decode(
            "latin-1"
        )
        layer_blob = build_gzip_tar(
            {"app/config.py": "TOKEN = 'x'", "app/big.bin": incompressible}
        )
        assert len(layer_blob) > 10 * 1024  # larger than tarfile's read buffer
        MANIFESTS_BY_DIGEST[IMAGE_DIGEST] = undersized_manifest
        BLOBS_BY_DIGEST[CONFIG_DIGEST] = json.dumps(CONFIG_JSON).encode()
        BLOBS_BY_DIGEST[LAYER_DIGEST] = layer_blob

        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        with (
            patch(_REQUESTS_GET, new=mock_requests_get),
            patch(
                "prowler.providers.aws.services.ecr.image_inspection.MAX_LAYER_DOWNLOAD_BYTES",
                len(layer_blob) - 1,
            ),
        ):
            scan_data = ImageInspector().fetch_image_scan_data(
                ecr_client, AWS_ACCOUNT_NUMBER, REPO_NAME, IMAGE_DIGEST
            )

        # The over-cap layer is disclosed via truncated, and the config-derived
        # env/history (fetched independently of the layer) are still returned.
        assert scan_data is not None
        assert scan_data.truncated is True
        assert scan_data.env == ["PATH=/usr/bin", "TOKEN=super-secret-value"]
