import zlib
from base64 import b64decode

from prowler.config.config import encoding_format_utf_8
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.logger import logger
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_launch_template_no_secrets(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = ec2_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = ec2_client.audit_config.get("secrets_validate", False)
        templates = list(ec2_client.launch_templates)

        # Track versions whose User Data cannot be decoded so the template is
        # surfaced (MANUAL) instead of silently claiming no secrets were found.
        undecodable_versions = {}

        # Collect the decoded User Data of every (template, version) and scan it
        # all in batched Kingfisher invocations instead of one subprocess per
        # version. Versions whose User Data cannot be decoded are recorded above.
        def payloads():
            for template_index, template in enumerate(templates):
                for version_index, version in enumerate(template.versions):
                    if not version.template_data.user_data:
                        continue
                    user_data = b64decode(version.template_data.user_data)
                    try:
                        if user_data[0:2] == b"\x1f\x8b":  # GZIP magic number
                            user_data = zlib.decompress(
                                user_data, zlib.MAX_WBITS | 32
                            ).decode(encoding_format_utf_8)
                        else:
                            user_data = user_data.decode(encoding_format_utf_8)
                    except UnicodeDecodeError as error:
                        logger.warning(
                            f"{template.region} -- Unable to decode User Data in EC2 Launch Template {template.name} version {version.version_number}: {error}"
                        )
                        undecodable_versions.setdefault(template_index, []).append(
                            version.version_number
                        )
                        continue
                    except Exception as error:
                        logger.error(
                            f"{template.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                        undecodable_versions.setdefault(template_index, []).append(
                            version.version_number
                        )
                        continue
                    yield (template_index, version_index), user_data

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for template_index, template in enumerate(templates):
            report = Check_Report_AWS(metadata=self.metadata(), resource=template)

            if scan_error and any(
                version.template_data.user_data for version in template.versions
            ):
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan EC2 Launch Template {template.name} User Data "
                    f"for secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            versions_with_secrets = []
            all_secrets = []

            for version_index, version in enumerate(template.versions):
                version_secrets = batch_results.get((template_index, version_index))
                if version_secrets:
                    all_secrets.extend(version_secrets)
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in version_secrets
                        ]
                    )
                    versions_with_secrets.append(
                        f"Version {version.version_number}: {secrets_string}"
                    )

            undecodable = undecodable_versions.get(template_index, [])
            if len(versions_with_secrets) > 0:
                report.status = "FAIL"
                report.status_extended = f"Potential secret found in User Data for EC2 Launch Template {template.name} in template versions: {', '.join(versions_with_secrets)}."
                annotate_verified_secrets(report, all_secrets)
            elif undecodable:
                report.status = "MANUAL"
                report.status_extended = f"Could not decode User Data for EC2 Launch Template {template.name} versions: {', '.join(str(version_number) for version_number in undecodable)}; manual review is required to scan for secrets."
            else:
                report.status = "PASS"
                report.status_extended = f"No secrets found in User Data of any version for EC2 Launch Template {template.name}."

            findings.append(report)

        return findings
