import re

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.appengine.appengine_client import appengine_client

# Standard environment runtimes look like "php82"; flexible ones are just "php"
PHP_RUNTIME_RE = re.compile(r"^php(?P<major>\d)(?P<minor>\d+)?$", re.IGNORECASE)


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".")) if value else ()


class appengine_version_php_runtime_supported(Check):
    """Check that serving App Engine versions run a supported PHP runtime."""

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        # `or` covers an explicit null in the config file, which .get() would return as None
        minimum = (
            appengine_client.audit_config.get("appengine_php_min_version") or "8.2"
        )

        for version in appengine_client.versions:
            runtime = version.runtime.lower()
            if not runtime.startswith("php") or version.serving_status != "SERVING":
                continue

            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=version,
                resource_id=version.id,
            )
            match = PHP_RUNTIME_RE.match(runtime)

            if version.env.lower() in ("flex", "flexible") or not (
                match and match["minor"]
            ):
                report.status = "MANUAL"
                report.status_extended = f"App Engine version {version.name} runs on the flexible environment with runtime '{version.runtime}', which is not patched in place; redeploy it on a fixed PHP release ({minimum} or newer) and verify the image."
            else:
                php_version = f"{match['major']}.{match['minor']}"
                if _version_tuple(php_version) < _version_tuple(minimum):
                    report.status = "FAIL"
                    report.status_extended = f"App Engine version {version.name} runs PHP {php_version} ('{version.runtime}'), a runtime that no longer receives security fixes (minimum supported version is {minimum})."
                else:
                    report.status = "PASS"
                    report.status_extended = f"App Engine version {version.name} runs PHP {php_version} ('{version.runtime}'), a supported runtime that receives security fixes automatically."

            findings.append(report)

        return findings
