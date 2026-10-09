"""Check that app registration certificates are not expired or expiring soon."""

from datetime import datetime, timedelta, timezone
from math import ceil

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_app_registration_certificate_not_expired(Check):
    """Ensure that application registration certificates (keyCredentials) are not expired or expiring soon.

    This check evaluates certificate credentials on Microsoft Entra ID
    application registrations and reports those with certificates that are
    already expired or will expire within a configurable threshold (default
    30 days). Client secrets (passwordCredentials) are deliberately excluded
    because they are already covered by
    ``entra_app_registration_client_secret_unused``.

    Certificates are deduplicated by ``customKeyIdentifier`` (thumbprint)
    before evaluation so that Sign/Verify entries for the same certificate
    are only counted once.

    - PASS: Every certificate on the app has endDateTime beyond the threshold.
    - FAIL: At least one certificate is expired or expiring within the threshold.
    - MANUAL: Certificate expiry data could not be retrieved (API error) or a
      certificate has a missing endDateTime and no other certificate on the
      app FAILs.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        if entra_client.app_registrations_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="App registrations",
                resource_id="applications",
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate app registration certificate expiry: "
                f"{entra_client.app_registrations_error}."
            )
            findings.append(report)
            return findings

        threshold_days = entra_client.audit_config.get(
            "app_registration_certificate_expiration_threshold_days", 30
        )
        now = datetime.now(timezone.utc)
        threshold_date = now + timedelta(days=threshold_days)

        for app_id, app in entra_client.app_registrations.items():
            if not app.key_credentials:
                continue

            # Deduplicate certificates by customKeyIdentifier (thumbprint).
            # The same certificate appears once per usage (Sign / Verify)
            # with the same thumbprint. Group by customKeyIdentifier, falling
            # back to keyId when the thumbprint is empty.
            seen_identifiers: set[str] = set()
            unique_certs = []
            for cred in app.key_credentials:
                dedup_key = cred.custom_key_identifier or cred.key_id
                if dedup_key in seen_identifiers:
                    continue
                seen_identifiers.add(dedup_key)
                unique_certs.append(cred)

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=app,
                resource_name=app.name or app.app_id,
                resource_id=app_id,
            )

            offending_details: list[str] = []
            has_missing_date = False

            for cred in unique_certs:
                cert_label = cred.display_name or cred.key_id

                if cred.end_date_time is None:
                    has_missing_date = True
                    continue

                # Normalise naive datetimes to UTC.
                end_dt = cred.end_date_time
                if end_dt.tzinfo is None:
                    end_dt = end_dt.replace(tzinfo=timezone.utc)
                else:
                    end_dt = end_dt.astimezone(timezone.utc)

                if end_dt < now:
                    # Already expired.
                    days_ago = ceil((now - end_dt).total_seconds() / 86400)
                    offending_details.append(
                        f"'{cert_label}' (expired {end_dt.strftime('%Y-%m-%d')}, "
                        f"{days_ago} day(s) ago)"
                    )
                elif end_dt <= threshold_date:
                    # Expiring soon.
                    days_left = ceil((end_dt - now).total_seconds() / 86400)
                    offending_details.append(
                        f"'{cert_label}' (expires {end_dt.strftime('%Y-%m-%d')}, "
                        f"in {days_left} day(s))"
                    )

            if offending_details:
                report.status = "FAIL"
                count = len(offending_details)
                report.status_extended = (
                    f"App registration '{app.name}' has {count} certificate(s) "
                    f"expired or expiring within {threshold_days} days: "
                    f"{', '.join(offending_details)}."
                )
            elif has_missing_date:
                report.status = "MANUAL"
                report.status_extended = (
                    f"App registration '{app.name}' has certificate(s) with "
                    f"missing expiry date that cannot be evaluated."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App registration '{app.name}' has all certificates valid "
                    f"beyond {threshold_days} days."
                )

            findings.append(report)

        return findings
