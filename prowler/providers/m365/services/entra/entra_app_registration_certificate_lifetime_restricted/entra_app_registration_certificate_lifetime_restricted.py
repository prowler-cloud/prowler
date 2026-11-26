import math
from datetime import datetime, timezone

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_app_registration_certificate_lifetime_restricted(Check):
    """Ensure that app registration certificates do not have excessive validity periods.

    This check evaluates each application registration in Microsoft Entra ID that
    has at least one certificate credential (keyCredentials). It verifies that no
    non-expired certificate has a validity period longer than a configurable
    maximum (default 365 days). Certificates are deduplicated by thumbprint
    (customKeyIdentifier) before evaluation so that Sign/Verify pairs for the
    same certificate are counted once.

    - PASS: Every non-expired certificate on the app has a validity period within
      the allowed maximum, or all certificates are already expired.
    - FAIL: At least one non-expired certificate has a validity period exceeding
      the allowed maximum.
    - MANUAL: The application list could not be read, or a certificate has
      missing date information preventing lifetime calculation and no other
      certificate on the app already FAILs.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the certificate lifetime check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # If the app registration data could not be retrieved, emit a single
        # tenant-level MANUAL finding.
        if entra_client.app_registrations_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="App registrations",
                resource_id="applications",
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate certificate lifetimes on app registrations: "
                f"{entra_client.app_registrations_error}. "
                f"Verify that the Directory.Read.All permission is granted to "
                f"the scanning application."
            )
            findings.append(report)
            return findings

        max_days = entra_client.audit_config.get(
            "app_registration_certificate_max_validity_days"
        )
        if max_days is None:  # unset or left empty in config.yaml
            max_days = 365
        now = datetime.now(timezone.utc)

        for app_id, app in entra_client.app_registrations.items():
            # Skip apps without any certificate credentials.
            if not app.key_credentials:
                continue

            # Deduplicate certificates: the same certificate appears once per
            # usage (Sign and Verify) with the same thumbprint in
            # custom_key_identifier.  Group by thumbprint, falling back to
            # key_id when the thumbprint is absent.
            seen_groups: dict[str, list] = {}
            for cred in app.key_credentials:
                group_key = cred.custom_key_identifier or cred.key_id
                if group_key not in seen_groups:
                    seen_groups[group_key] = []
                seen_groups[group_key].append(cred)

            failing_certs: list[str] = []
            undeterminable_certs: list[str] = []

            for _group_key, creds in seen_groups.items():
                # Pick the first credential in each group as the representative.
                cred = creds[0]
                cert_label = cred.display_name or cred.key_id

                # If end_date_time is missing we cannot determine expiry or
                # lifetime.
                if cred.end_date_time is None:
                    undeterminable_certs.append(cert_label)
                    continue

                end_dt = _ensure_utc(cred.end_date_time)

                # Skip expired certificates -- they cannot authenticate.
                if end_dt < now:
                    continue

                # If start_date_time is missing on a non-expired certificate we
                # cannot determine the lifetime.
                if cred.start_date_time is None:
                    undeterminable_certs.append(cert_label)
                    continue

                start_dt = _ensure_utc(cred.start_date_time)
                lifetime = end_dt - start_dt
                lifetime_days = lifetime.total_seconds() / 86400

                if lifetime_days > max_days:
                    display_days = math.ceil(lifetime_days)
                    expiry_date = end_dt.strftime("%Y-%m-%d")
                    failing_certs.append(
                        f"'{cert_label}' ({display_days} days, expires {expiry_date})"
                    )

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=app,
                resource_name=app.name or app.app_id,
                resource_id=app_id,
            )

            if failing_certs:
                report.status = "FAIL"
                cert_list = ", ".join(failing_certs)
                msg = (
                    f"App registration '{app.name}' has {len(failing_certs)} "
                    f"certificate(s) valid for longer than {max_days} days: "
                    f"{cert_list}."
                )
                if undeterminable_certs:
                    undet_list = ", ".join(f"'{c}'" for c in undeterminable_certs)
                    msg = (
                        f"{msg[:-1]}; additionally, lifetime could not be "
                        f"determined for: {undet_list}."
                    )
                report.status_extended = msg
            elif undeterminable_certs:
                report.status = "MANUAL"
                undet_list = ", ".join(f"'{c}'" for c in undeterminable_certs)
                report.status_extended = (
                    f"App registration '{app.name}' has certificate(s) whose "
                    f"lifetime could not be determined (missing dates): "
                    f"{undet_list}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App registration '{app.name}' has all certificate "
                    f"validity periods within {max_days} days."
                )

            findings.append(report)

        return findings


def _ensure_utc(dt: datetime) -> datetime:
    """Normalise a datetime to UTC.

    If the datetime is naive (no tzinfo), it is assumed to be UTC. Otherwise it
    is converted to UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
