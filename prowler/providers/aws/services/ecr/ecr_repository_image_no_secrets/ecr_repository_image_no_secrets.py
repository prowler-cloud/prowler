import json
import tarfile
import tempfile
import urllib.request
from collections import defaultdict

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.ecr.ecr_client import ecr_client

# Maximum size (in bytes) for a single layer download. Layers larger than this
# are skipped to prevent excessive memory usage and long scan times.
MAX_LAYER_DOWNLOAD_SIZE = 52428800  # 50 MB
# Timeout (seconds) for layer download requests to avoid hanging on slow
# or unresponsive connections.
LAYER_DOWNLOAD_TIMEOUT = 30
# Maximum size (in bytes) for a single file extracted from a tar layer.
# Files larger than this are skipped during text scanning.
MAX_TAR_MEMBER_SIZE = 1048576  # 1 MB


class ecr_repository_image_no_secrets(Check):
    """Check for secrets in ECR container images.

    This check scans the latest tagged image in each ECR repository for
    hardcoded secrets such as API keys, tokens, passwords, and connection
    strings by downloading the image layers and running a secrets scan.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the ECR image secrets check.

        Scans the latest tagged image of each ECR repository for hardcoded
        secrets. Images that cannot be retrieved or scanned are reported as
        MANUAL for operator review.

        Returns:
            list of Check_Report_AWS: findings for each ECR repository.
        """
        findings = []
        if not ecr_client.registries:
            return findings

        secrets_ignore_patterns = ecr_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        secrets_ignore_files = (
            ecr_client.audit_config.get("secrets_ignore_files", []) or []
        )
        validate = ecr_client.audit_config.get("secrets_validate", False)

        # Collect all image layer payloads across repositories.
        # Each payload is keyed by (repository_index, layer_index) so findings
        # can be grouped back per repository.
        repositories_with_images = []
        repos_with_data = set()
        # Track repositories where data collection failed so they emit MANUAL
        # rather than PASS.
        repos_with_incomplete_data = set()

        def image_payloads():
            for repo_index, repository in enumerate(repositories_with_images):
                if not repository.images_details:
                    continue
                # Only check the latest (most recently pushed) image
                image = repository.images_details[-1]
                if not image.latest_digest:
                    continue

                client = ecr_client.regional_clients.get(repository.region)
                if not client:
                    continue

                try:
                    # Get the image manifest and config to extract layer info
                    response = client.batch_get_image(
                        repositoryName=repository.name,
                        imageIds=[
                            {
                                "imageDigest": image.latest_digest,
                            }
                        ],
                    )
                except Exception as error:
                    logger.warning(
                        f"{ecr_repository_image_no_secrets.__name__}: "
                        f"ECR batch_get_image failed for repository "
                        f"{repository.name}: {error}"
                    )
                    repos_with_incomplete_data.add(repo_index)
                    continue

                if not response.get("images"):
                    repos_with_incomplete_data.add(repo_index)
                    continue

                try:
                    image_manifest = json.loads(
                        response["images"][0]["imageManifest"]
                    )
                except (KeyError, json.JSONDecodeError) as error:
                    logger.warning(
                        f"{ecr_repository_image_no_secrets.__name__}: "
                        f"Could not parse image manifest for repository "
                        f"{repository.name}: {error}"
                    )
                    repos_with_incomplete_data.add(repo_index)
                    continue

                # Scan the image configuration for embedded secrets
                config_digest = image_manifest.get("config", {}).get("digest")
                if config_digest:
                    try:
                        layer_response = client.get_download_url_for_layer(
                            repositoryName=repository.name,
                            layerDigest=config_digest,
                        )
                        layer_url = layer_response.get("downloadUrl")
                        if layer_url:
                            with urllib.request.urlopen(
                                layer_url, timeout=LAYER_DOWNLOAD_TIMEOUT
                            ) as resp:
                                # Read at most MAX_LAYER_DOWNLOAD_SIZE + 1 bytes
                                # to detect oversized configs.
                                config_content = resp.read(
                                    MAX_LAYER_DOWNLOAD_SIZE + 1
                                )
                                if len(config_content) > MAX_LAYER_DOWNLOAD_SIZE:
                                    logger.warning(
                                        f"{ecr_repository_image_no_secrets.__name__}: "
                                        f"Config layer for repository "
                                        f"{repository.name} exceeds download limit, "
                                        f"skipping config scan."
                                    )
                                    repos_with_incomplete_data.add(repo_index)
                                else:
                                    config_text = config_content.decode(
                                        "latin-1", errors="replace"
                                    )
                                    repos_with_data.add(repo_index)
                                    yield (
                                        repo_index,
                                        f"config-{config_digest}",
                                    ), config_text
                    except Exception as error:
                        logger.warning(
                            f"{ecr_repository_image_no_secrets.__name__}: "
                            f"Could not download config layer for repository "
                            f"{repository.name}: {error}"
                        )
                        repos_with_incomplete_data.add(repo_index)

                # Scan each layer for embedded secrets
                for layer_index, layer in enumerate(
                    image_manifest.get("layers", [])
                ):
                    layer_digest = layer.get("digest")
                    if not layer_digest:
                        continue
                    try:
                        layer_response = client.get_download_url_for_layer(
                            repositoryName=repository.name,
                            layerDigest=layer_digest,
                        )
                        layer_url = layer_response.get("downloadUrl")
                        if layer_url:
                            with urllib.request.urlopen(
                                layer_url, timeout=LAYER_DOWNLOAD_TIMEOUT
                            ) as resp:
                                # Bound the download size to avoid excessive
                                # memory usage on very large layers.
                                layer_data = resp.read(
                                    MAX_LAYER_DOWNLOAD_SIZE + 1
                                )
                                if len(layer_data) > MAX_LAYER_DOWNLOAD_SIZE:
                                    logger.warning(
                                        f"{ecr_repository_image_no_secrets.__name__}: "
                                        f"Layer {layer_digest} for repository "
                                        f"{repository.name} exceeds download limit, "
                                        f"skipping layer scan."
                                    )
                                    repos_with_incomplete_data.add(repo_index)
                                    continue
                            repos_with_data.add(repo_index)
                            # Try to extract tar content for text scanning
                            try:
                                with tempfile.NamedTemporaryFile() as tmp:
                                    tmp.write(layer_data)
                                    tmp.flush()
                                    with tarfile.open(tmp.name, "r:*") as tar:
                                        for member in tar.getmembers():
                                            if (
                                                member.isfile()
                                                and member.size
                                                < MAX_TAR_MEMBER_SIZE
                                            ):
                                                f = tar.extractfile(member)
                                                if f:
                                                    # Read per-member content
                                                    # with a limit to avoid
                                                    # unbounded memory use.
                                                    member_content = f.read(
                                                        MAX_TAR_MEMBER_SIZE
                                                    )
                                                    content = (
                                                        member_content.decode(
                                                            "latin-1",
                                                            errors="replace",
                                                        )
                                                    )
                                                    yield (
                                                        repo_index,
                                                        f"layer{layer_index}-{member.name}",
                                                    ), content
                            except Exception:
                                # If not a valid tar, scan raw content as text
                                try:
                                    content = layer_data.decode(
                                        "latin-1", errors="replace"
                                    )
                                    yield (
                                        repo_index,
                                        f"layer{layer_index}-{layer_digest}",
                                    ), content
                                except Exception:
                                    pass
                    except Exception as error:
                        logger.warning(
                            f"{ecr_repository_image_no_secrets.__name__}: "
                            f"Could not download layer {layer_digest} for "
                            f"repository {repository.name}: {error}"
                        )
                        repos_with_incomplete_data.add(repo_index)

        # Build list of repositories with images
        for registry in ecr_client.registries.values():
            for repository in registry.repositories:
                if repository.images_details:
                    repositories_with_images.append(repository)

        if not repositories_with_images:
            return findings

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                image_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        if scan_error:
            for repository in repositories_with_images:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=repository
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan ECR repository {repository.name} images for "
                    f"secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
            return findings

        # Group findings by repository index
        findings_by_repo = defaultdict(dict)
        for (repo_index, file_name), file_findings in batch_results.items():
            findings_by_repo[repo_index][file_name] = file_findings

        for repo_index, repository in enumerate(repositories_with_images):
            report = Check_Report_AWS(metadata=self.metadata(), resource=repository)

            # If no image data was collected for this repository, or data
            # collection was incomplete, report MANUAL so the operator can
            # investigate.
            if (
                repo_index not in repos_with_data
                or repo_index in repos_with_incomplete_data
            ):
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not collect image data for ECR repository "
                    f"{repository.name}; manual review is required."
                )
                findings.append(report)
                continue

            image_digest = repository.images_details[-1].latest_digest
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in ECR repository {repository.name} "
                f"image {image_digest}."
            )

            files_with_secrets = findings_by_repo.get(repo_index)
            if files_with_secrets:
                all_secrets = []
                secrets_findings = []
                for file_name, file_findings in files_with_secrets.items():
                    all_secrets.extend(file_findings)
                    secrets_string = ", ".join(
                        f"{secret['type']} on line {secret['line_number']}"
                        for secret in file_findings
                    )
                    secrets_findings.append(f"{file_name}: {secrets_string}")

                final_output_string = "; ".join(secrets_findings)
                report.status = "FAIL"
                report.status_extended = (
                    f"Potential {'secrets' if len(secrets_findings) > 1 else 'secret'} "
                    f"found in ECR repository {repository.name} image {image_digest} -> "
                    f"{final_output_string}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings