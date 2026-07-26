import tarfile
from concurrent.futures import as_completed
from datetime import datetime
from io import BytesIO
from json import loads
from typing import Optional

import requests
import zstd
from botocore.exceptions import ClientError
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService

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


class ECR(AWSService):
    """AWS Elastic Container Registry service."""

    def __init__(self, provider):
        """Discover registries, repositories, policies, and image metadata."""
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.registry_id = self.audited_account
        self.registries = {}
        self.__threading_call__(self._describe_registries_and_repositories)
        self.__threading_call__(self._describe_repository_policies)
        self.__threading_call__(self._get_image_details)
        self.__threading_call__(self._get_repository_lifecycle_policy)
        self.__threading_call__(self._get_registry_scanning_configuration)
        self.__threading_call__(self._list_tags_for_resource)

    def _describe_registries_and_repositories(self, regional_client):
        """Populate the registry and its repositories for one region."""
        logger.info("ECR - Describing registries and repositories...")
        regional_registry_repositories = []
        try:
            describe_ecr_paginator = regional_client.get_paginator(
                "describe_repositories"
            )
            for page in describe_ecr_paginator.paginate():
                for repository in page["repositories"]:
                    if not self.audit_resources or (
                        is_resource_filtered(
                            repository["repositoryArn"], self.audit_resources
                        )
                    ):
                        regional_registry_repositories.append(
                            Repository(
                                name=repository["repositoryName"],
                                arn=repository["repositoryArn"],
                                registry_id=repository["registryId"],
                                region=regional_client.region,
                                scan_on_push=repository["imageScanningConfiguration"][
                                    "scanOnPush"
                                ],
                                immutability=repository.get(
                                    "imageTagMutability", "MUTABLE"
                                ),
                                policy=None,
                                images_details=[],
                                lifecycle_policy=None,
                            )
                        )
            # The default ECR registry is assumed
            self.registries[regional_client.region] = Registry(
                id=self.registry_id,
                arn=f"arn:{self.audited_partition}:ecr:{regional_client.region}:{self.audited_account}:registry/{self.registry_id}",
                region=regional_client.region,
                repositories=regional_registry_repositories,
            )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _describe_repository_policies(self, regional_client):
        """Fetch and attach each repository's resource policy, if any."""
        logger.info("ECR - Describing repository policies...")
        try:
            if regional_client.region in self.registries:
                for repository in self.registries[regional_client.region].repositories:
                    client = self.regional_clients[repository.region]
                    try:
                        policy = client.get_repository_policy(
                            repositoryName=repository.name
                        )
                        if "policyText" in policy:
                            repository.policy = loads(policy["policyText"])
                    except ClientError as error:
                        if (
                            error.response["Error"]["Code"]
                            == "RepositoryPolicyNotFoundException"
                        ):
                            logger.warning(
                                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                            )
                            repository.policy = {}

        except Exception as error:
            if "RepositoryPolicyNotFoundException" not in str(error):
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_repository_lifecycle_policy(self, regional_client):
        """Fetch and attach each repository's lifecycle policy, if any."""
        logger.info("ECR - Getting repository lifecycle policy...")
        try:
            if regional_client.region in self.registries:
                for repository in self.registries[regional_client.region].repositories:
                    client = self.regional_clients[repository.region]
                    try:
                        policy = client.get_lifecycle_policy(
                            repositoryName=repository.name
                        )
                        if "lifecyclePolicyText" in policy:
                            repository.lifecycle_policy = policy["lifecyclePolicyText"]
                    except ClientError as error:
                        if (
                            error.response["Error"]["Code"]
                            == "LifecyclePolicyNotFoundException"
                        ):
                            logger.warning(
                                f"{regional_client.region} --"
                                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                                f" {error}"
                            )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_image_details(self, regional_client):
        """Populate each scan-on-push repository's scannable, tagged images."""
        logger.info("ECR - Getting images details...")
        try:
            if regional_client.region in self.registries:
                for repository in self.registries[regional_client.region].repositories:
                    # There is nothing to do if the repository is not scanning pushed images
                    if repository.scan_on_push:
                        client = self.regional_clients[repository.region]
                        describe_images_paginator = client.get_paginator(
                            "describe_images"
                        )
                        for page in describe_images_paginator.paginate(
                            registryId=self.registries[regional_client.region].id,
                            repositoryName=repository.name,
                            PaginationConfig={"PageSize": 1000},
                        ):
                            for image in page["imageDetails"]:
                                # The following condition is required since sometimes
                                # the AWS ECR API returns None using the iterator
                                if image is not None:
                                    artifact_media_type = image.get(
                                        "artifactMediaType", None
                                    )
                                    tags = image.get("imageTags", [])
                                    if ECR._is_artifact_scannable(
                                        artifact_media_type, tags
                                    ):
                                        severity_counts = None
                                        last_scan_status = None
                                        image_digest = image.get("imageDigest")
                                        latest_tag = image.get("imageTags", ["None"])[0]
                                        image_pushed_at = image.get("imagePushedAt")
                                        image_scan_findings_field_name = (
                                            "imageScanFindingsSummary"
                                        )
                                        if "docker" in artifact_media_type:
                                            type = "Docker"
                                        elif "oci" in artifact_media_type:
                                            type = "OCI"
                                        else:
                                            type = ""

                                        # If imageScanStatus is not present or imageScanFindingsSummary is missing,
                                        # we need to call DescribeImageScanFindings because AWS' new version of
                                        # basic scanning does not support imageScanFindingsSummary and imageScanStatus
                                        # in the DescribeImages API.
                                        if "imageScanStatus" not in image:
                                            try:
                                                # use "image" for scan findings to get data the same way as for an image
                                                image = (
                                                    client.describe_image_scan_findings(
                                                        registryId=self.registries[
                                                            regional_client.region
                                                        ].id,
                                                        repositoryName=repository.name,
                                                        imageId={
                                                            "imageDigest": image_digest
                                                        },
                                                    )
                                                )
                                                image_scan_findings_field_name = (
                                                    "imageScanFindings"
                                                )
                                            except (
                                                client.exceptions.ImageNotFoundException
                                            ) as error:
                                                logger.warning(
                                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                                )
                                                continue
                                            except (
                                                client.exceptions.ScanNotFoundException
                                            ) as error:
                                                logger.warning(
                                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                                )
                                                continue
                                            except Exception as error:
                                                logger.error(
                                                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                                )
                                                continue

                                        if "imageScanStatus" in image:
                                            last_scan_status = image["imageScanStatus"][
                                                "status"
                                            ]

                                        if image_scan_findings_field_name in image:
                                            severity_counts = FindingSeverityCounts(
                                                critical=0, high=0, medium=0
                                            )
                                            finding_severity_counts = image[
                                                image_scan_findings_field_name
                                            ].get("findingSeverityCounts", {})
                                            severity_counts.critical = (
                                                finding_severity_counts.get(
                                                    "CRITICAL", 0
                                                )
                                            )
                                            severity_counts.high = (
                                                finding_severity_counts.get("HIGH", 0)
                                            )
                                            severity_counts.medium = (
                                                finding_severity_counts.get("MEDIUM", 0)
                                            )

                                        repository.images_details.append(
                                            ImageDetails(
                                                latest_tag=latest_tag,
                                                image_pushed_at=image_pushed_at,
                                                latest_digest=image_digest,
                                                scan_findings_status=last_scan_status,
                                                scan_findings_severity_count=severity_counts,
                                                artifact_media_type=artifact_media_type,
                                                type=type,
                                            )
                                        )
                        # Sort the repository images by date pushed
                        repository.images_details.sort(
                            key=lambda image: image.image_pushed_at
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_tags_for_resource(self, regional_client):
        """Fetch and attach each repository's resource tags."""
        logger.info("ECR - List Tags...")
        try:
            if regional_client.region in self.registries:
                for repository in self.registries[regional_client.region].repositories:
                    try:
                        regional_client = self.regional_clients[repository.region]
                        response = regional_client.list_tags_for_resource(
                            resourceArn=repository.arn
                        )["tags"]
                        repository.tags = response

                    except ClientError as error:
                        if (
                            error.response["Error"]["Code"]
                            == "RepositoryNotFoundException"
                        ):
                            logger.warning(
                                f"{regional_client.region} --"
                                f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                                f" {error}"
                            )
                            continue
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_registry_scanning_configuration(self, regional_client):
        """Fetch and attach the registry's image-scanning configuration."""
        logger.info("ECR - Getting Registry Scanning Configuration...")
        try:
            if regional_client.region in self.registries:
                response = regional_client.get_registry_scanning_configuration()
                rules = []
                for rule in response.get("scanningConfiguration").get("rules", []):
                    rules.append(
                        ScanningRule(
                            scan_frequency=rule.get("scanFrequency"),
                            scan_filters=rule.get("repositoryFilters", []),
                        )
                    )

                self.registries[regional_client.region].scan_type = response.get(
                    "scanningConfiguration"
                ).get("scanType", "BASIC")
                self.registries[regional_client.region].rules = rules
        except ClientError as error:
            if error.response["Error"][
                "Code"
            ] == "ValidationException" and "GetRegistryScanningConfiguration operation: This feature is disabled" in str(
                error
            ):
                self.registries[regional_client.region].scan_type = "BASIC"
                self.registries[regional_client.region].rules = []
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_image_scan_data(self):
        """Lazily fetch manifest, config, and layer file contents for the latest image.

        Only the most recently pushed image in each repository is scanned
        (images_details is sorted ascending by push date, so the latest is
        the last element) to bound cost on repositories with many tags.

        Not called from __init__: this is only invoked by the
        ecr_repository_image_no_secrets check, since it downloads and
        decompresses image layers and is significantly more expensive than
        the metadata gathered above.

        Yields:
            Tuple of (Repository, ImageDetails, Optional[ImageScanData]). The
            scan data is None when the image manifest could not be resolved
            or retrieved, so the caller can report it rather than drop it.
        """
        logger.info("ECR - Fetching image manifests, configs, and layers...")
        images_to_fetch = {
            self.thread_pool.submit(self._fetch_image_scan_data, repository, image): (
                repository,
                image,
            )
            for registry in self.registries.values()
            for repository in registry.repositories
            for image in (
                [repository.images_details[-1]] if repository.images_details else []
            )
        }

        for future in as_completed(images_to_fetch):
            repository, image = images_to_fetch[future]
            scan_data = None
            try:
                scan_data = future.result()
            except Exception as error:
                logger.error(
                    f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            yield repository, image, scan_data

    def _fetch_image_scan_data(self, repository, image) -> Optional["ImageScanData"]:
        """Resolve one image's manifest and return its scannable content.

        Downloads the config blob (environment variables, build history)
        and every filesystem layer's file contents, bounded by the module's
        size/count limits.

        Returns:
            An ImageScanData, or None if the manifest could not be resolved.
        """
        client = self.regional_clients[repository.region]
        registry_id = self.registries[repository.region].id

        manifest = self._resolve_image_manifest(
            client, registry_id, repository.name, image.latest_digest
        )
        if manifest is None:
            return None

        env = []
        history = []
        config_digest = manifest.get("config", {}).get("digest")
        if config_digest:
            config_bytes = self._download_layer(
                client,
                registry_id,
                repository.name,
                config_digest,
                max_bytes=MAX_FILE_BYTES,
            )
            if config_bytes is not None:
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
                        f"{repository.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

        files = []
        total_bytes = 0
        truncated = False
        for layer in manifest.get("layers", []):
            if (
                len(files) >= MAX_FILES_PER_IMAGE
                or total_bytes >= MAX_TOTAL_BYTES_PER_IMAGE
            ):
                truncated = True
                break

            layer_digest = layer.get("digest")
            layer_size = layer.get("size", 0)
            if layer_size and layer_size > MAX_LAYER_DOWNLOAD_BYTES:
                truncated = True
                continue

            layer_bytes = self._download_layer(
                client,
                registry_id,
                repository.name,
                layer_digest,
                max_bytes=MAX_LAYER_DOWNLOAD_BYTES,
            )
            if layer_bytes is None:
                truncated = True
                continue

            tar_stream = self._open_layer_tar(
                layer_bytes,
                layer.get("mediaType", ""),
                remaining_budget=MAX_TOTAL_BYTES_PER_IMAGE - total_bytes,
            )
            if tar_stream is None:
                truncated = True
                continue
            # The compressed blob is no longer needed once decompressed into
            # tar_stream; drop it so it can be freed during the (often
            # longer) member-iteration below instead of lingering alongside
            # the decompressed copy.
            layer_bytes = None

            with tar_stream:
                for member in tar_stream:
                    if (
                        len(files) >= MAX_FILES_PER_IMAGE
                        or total_bytes >= MAX_TOTAL_BYTES_PER_IMAGE
                    ):
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
                    except Exception:
                        continue
                    files.append(
                        ImageScanFile(
                            path=member.name,
                            layer_digest=layer_digest,
                            content=content,
                        )
                    )
                    total_bytes += member.size

        return ImageScanData(env=env, history=history, files=files, truncated=truncated)

    def _resolve_image_manifest(
        self, client, registry_id, repository_name, image_digest
    ) -> Optional[dict]:
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
                return None

            if media_type in _MANIFEST_LIST_MEDIA_TYPES:
                child_digest = self._select_child_manifest_digest(manifest)
                if not child_digest:
                    return None
                manifest, _ = self._batch_get_manifest(
                    client, registry_id, repository_name, child_digest
                )
            if manifest is not None and not (
                manifest.get("config") or manifest.get("layers")
            ):
                # A resolved manifest with neither a config nor layers has
                # nothing to scan (e.g. a nested manifest list, or an
                # unsupported manifest shape) — treat it as unresolvable so
                # the caller reports MANUAL instead of a false PASS.
                return None
            return manifest
        except Exception as error:
            logger.error(
                f"{client.meta.region_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

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
    def _download_layer(
        client, registry_id, repository_name, layer_digest, max_bytes=None
    ) -> Optional[bytes]:
        """Download one layer or config blob via its presigned URL.

        Streams the response, aborting once `max_bytes` is exceeded, so a
        lying or oversized blob is never buffered in full.

        Returns:
            The blob's bytes, or None if it could not be downloaded or
            exceeded `max_bytes`.
        """
        try:
            response = client.get_download_url_for_layer(
                registryId=registry_id,
                repositoryName=repository_name,
                layerDigest=layer_digest,
            )
            download_url = response.get("downloadUrl")
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

    @staticmethod
    def _zstd_frame_content_size(data: bytes) -> Optional[int]:
        """Read the declared decompressed size from a zstd frame header.

        Parses the frame header fields (RFC 8878 3.1.1) needed to locate the
        Frame_Content_Size field without decompressing any data.

        Returns:
            The declared decompressed size, or None if the input isn't a
            standard zstd frame or the size is absent from its header.
        """
        if len(data) < 6 or data[:4] != b"\x28\xb5\x2f\xfd":
            return None

        descriptor = data[4]
        single_segment = bool(descriptor & 0x20)
        fcs_flag = descriptor >> 6
        dict_id_size = {0: 0, 1: 1, 2: 2, 3: 4}[descriptor & 0x03]

        offset = 5
        if not single_segment:
            offset += 1  # Window_Descriptor byte
        offset += dict_id_size

        if single_segment:
            fcs_size = {0: 1, 1: 2, 2: 4, 3: 8}[fcs_flag]
        else:
            fcs_size = {0: 0, 1: 2, 2: 4, 3: 8}[fcs_flag]
        if fcs_size == 0 or len(data) < offset + fcs_size:
            return None

        content_size = int.from_bytes(data[offset : offset + fcs_size], "little")
        if fcs_size == 2:
            # Per the spec, the 2-byte encoding adds a 256 offset so it
            # can't overlap the 1-byte encoding's value range.
            content_size += 256
        return content_size

    @staticmethod
    def _open_layer_tar(layer_bytes: bytes, media_type: str, remaining_budget: int):
        """Open a downloaded layer's bytes as a tar archive by media type.

        Args:
            remaining_budget: Decompressed bytes still allowed for this
                image (MAX_TOTAL_BYTES_PER_IMAGE minus what prior layers
                already contributed), used to bound zstd decompression.

        Returns:
            An open TarFile for gzip, zstd, or uncompressed tar layers, or
            None for an unrecognized media type or a decompression failure.
        """
        try:
            if media_type.endswith("zstd"):
                # Unlike gzip (streamed incrementally by tarfile, with each
                # member's size checked before its content is read), zstd
                # decompression here happens all at once. Refuse to expand a
                # frame whose declared decompressed size is unknown or would
                # exceed what's left of the image's total budget, instead of
                # buffering an unbounded amount of untrusted data in memory.
                content_size = ECR._zstd_frame_content_size(layer_bytes)
                if content_size is None or content_size > remaining_budget:
                    return None
                return tarfile.open(
                    fileobj=BytesIO(zstd.decompress(layer_bytes)), mode="r:"
                )
            if media_type.endswith("gzip"):
                return tarfile.open(fileobj=BytesIO(layer_bytes), mode="r:gz")
            if media_type.endswith("tar"):
                return tarfile.open(fileobj=BytesIO(layer_bytes), mode="r:")
            return None
        except Exception as error:
            logger.warning(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    @staticmethod
    def _is_artifact_scannable(artifact_media_type: str, tags: list[str] = []) -> bool:
        """
        Check if an artifact is scannable based on its media type and tags.

        Args:
            artifact_media_type (str): The media type of the artifact.
            tags (list): The list of tags associated with the artifact.

        Returns:
            bool: True if the artifact is scannable, False otherwise.
        """
        try:
            if artifact_media_type is None:
                return False

            # Tools like GoogleContainerTools/jib uses `application/vnd.oci.image.config.v1+json`` also for signatures, which are not scannable.
            # Luckily, these are tagged with sha-<HASH-CODE>.sig, so that they can still be easily recognized.
            for tag in tags:
                if tag.startswith("sha256-") and tag.endswith(".sig"):
                    return False

            scannable_artifact_media_types = [
                "application/vnd.docker.container.image.v1+json",  # Docker image configuration
                "application/vnd.docker.image.rootfs.diff.tar",  # Docker image layer as a tar archive
                "application/vnd.docker.image.rootfs.diff.tar.gzip",  # Docker image layer that is compressed using gzip
                "application/vnd.oci.image.config.v1+json",  # OCI image configuration, but also used by GoogleContainerTools/jib for signatures
                "application/vnd.oci.image.layer.v1.tar",  # Uncompressed OCI image layer
                "application/vnd.oci.image.layer.v1.tar+gzip",  # Compressed OCI image layer
            ]

            return artifact_media_type in scannable_artifact_media_types
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False


class FindingSeverityCounts(BaseModel):
    """Count of an image's vulnerability scan findings by severity."""

    critical: int
    high: int
    medium: int


class ImageDetails(BaseModel):
    """A single scannable, tagged image within an ECR repository."""

    latest_tag: str
    latest_digest: str
    image_pushed_at: datetime
    scan_findings_status: Optional[str]
    scan_findings_severity_count: Optional[FindingSeverityCounts]
    artifact_media_type: Optional[str]
    type: str


class Repository(BaseModel):
    """An ECR repository and its policies, images, and tags."""

    name: str
    arn: str
    region: str
    registry_id = str
    scan_on_push: bool
    immutability: Optional[str]
    policy: Optional[dict]
    images_details: Optional[list[ImageDetails]]
    lifecycle_policy: Optional[str]
    tags: Optional[list] = []


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
    # True when a layer/file exceeded a configured size or count limit and
    # was not scanned, so PASS results can disclose partial coverage.
    truncated: bool = False


class ScanningRule(BaseModel):
    """A registry-level image-scanning rule and its repository filters."""

    scan_frequency: str
    scan_filters: list[dict]


class Registry(BaseModel):
    """An ECR registry: its repositories and scanning configuration."""

    id: str
    arn: str
    region: str
    repositories: list[Repository]
    scan_type: Optional[str]
    rules: Optional[list[ScanningRule]]
