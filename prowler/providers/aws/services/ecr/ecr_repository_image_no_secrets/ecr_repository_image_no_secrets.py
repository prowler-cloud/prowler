import json
import tarfile
import tempfile
from collections import defaultdict

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repository_image_no_secrets(Check):
    """Check for secrets in ECR container images.

    This check scans the latest tagged image in each ECR repository for
    hardcoded secrets such as API keys, tokens, passwords, and connection
    strings by downloading the image layers and running a secrets scan.
    """

    def execute(self):
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
                except Exception:
                    continue

                if not response.get("images"):
                    continue

                try:
                    image_manifest = json.loads(
                        response["images"][0]["imageManifest"]
                    )
                except (KeyError, json.JSONDecodeError):
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
                            import urllib.request

                            with urllib.request.urlopen(layer_url) as resp:
                                config_content = resp.read().decode(
                                    "latin-1", errors="replace"
                                )
                            yield (repo_index, f"config-{config_digest}"), config_content
                    except Exception:
                        pass

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
                            import urllib.request

                            with urllib.request.urlopen(layer_url) as resp:
                                layer_data = resp.read()
                            # Try to extract tar content for text scanning
                            try:
                                with tempfile.NamedTemporaryFile() as tmp:
                                    tmp.write(layer_data)
                                    tmp.flush()
                                    with tarfile.open(tmp.name, "r:*") as tar:
                                        for member in tar.getmembers():
                                            if member.isfile() and member.size < 1048576:
                                                f = tar.extractfile(member)
                                                if f:
                                                    content = f.read().decode(
                                                        "latin-1", errors="replace"
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
                    except Exception:
                        pass

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
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in ECR repository {repository.name} image."
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
                    f"found in ECR repository {repository.name} image -> "
                    f"{final_output_string}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
