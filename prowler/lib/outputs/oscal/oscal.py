import json
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from prowler.lib.outputs.oscal.models import (
    DEFAULT_IMPORT_AP_HREF,
    AssessmentResults,
    Metadata,
    Observation,
    OscalDocument,
    OscalFinding,
    Property,
    RelatedObservation,
    Result,
    Subject,
)


class OSCAL:
    """
    Transforms Prowler findings into NIST OSCAL 1.2.3 Assessment Results JSON format.
    """

    def __init__(
        self,
        findings: List[Any],
        file_path: Optional[str] = None,
        import_ap_href: str = DEFAULT_IMPORT_AP_HREF,
    ) -> None:
        """Build and hold the OSCAL document(s) for the given findings.

        Args:
            findings: Prowler finding objects to transform.
            file_path: Optional output path (used by callers that write
                straight to disk rather than via ``batch_write_data_to_file``).
            import_ap_href: The assessment-plan reference this run is
                evaluated against, emitted at ``assessment-results.import-ap.href``.
        """
        self.import_ap_href = import_ap_href
        self.file_path = file_path
        self.file_descriptor = None
        self._data: List[OscalDocument] = []
        if findings:
            self.transform(findings)

    @property
    def data(self) -> List[OscalDocument]:
        """The transformed OSCAL document(s), one per ``transform()`` call."""
        return self._data

    def transform(self, findings: List[Any]) -> None:
        """
        Transforms a list of Prowler findings into an OSCAL AssessmentResults document.
        """
        if not findings:
            return

        now_iso = datetime.now(timezone.utc).isoformat()
        first_finding = findings[0]
        account_uid = getattr(first_finding, "account_uid", "default-account")
        provider_name = (
            first_finding.metadata.Provider
            if hasattr(first_finding, "metadata")
            and hasattr(first_finding.metadata, "Provider")
            else "aws"
        )
        prowler_version = getattr(first_finding, "prowler_version", "4.0.0")

        metadata = Metadata(
            title=f"Prowler Security Assessment — {provider_name.upper()} ({account_uid})",
            published=now_iso,
            last_modified=now_iso,
            version=prowler_version,
            props=[
                Property(name="generator", value="Prowler", class_="tool"),
                Property(
                    name="generator-version", value=prowler_version, class_="version"
                ),
                Property(
                    name="account-id",
                    value=str(account_uid),
                    class_="provider-identity",
                ),
            ],
        )

        result_uuid = str(
            uuid.uuid5(uuid.NAMESPACE_DNS, f"prowler.result.{account_uid}")
        )
        result = Result(
            result_uuid=result_uuid,
            title=f"Assessment Results for {provider_name.upper()} Account {account_uid}",
            description="Automated technical control evaluation performed by Prowler.",
            start=now_iso,
            end=now_iso,
            props=[
                Property(name="assessment-type", value="automated", class_="mode"),
                Property(name="provider", value=provider_name, class_="provider"),
            ],
            observations=[],
            findings=[],
        )

        for finding in findings:
            finding_timestamp = (
                finding.timestamp.isoformat()
                if hasattr(finding, "timestamp")
                and isinstance(finding.timestamp, datetime)
                else now_iso
            )
            resource_uid = getattr(finding, "resource_uid", "resource-default")
            resource_name = getattr(finding, "resource_name", resource_uid)
            finding_uid = getattr(finding, "uid", str(uuid.uuid4()))
            region = getattr(finding, "region", "global")
            muted = getattr(finding, "muted", False)
            status_val = (
                finding.status.value
                if hasattr(finding.status, "value")
                else str(finding.status)
            )

            subject_uuid = str(
                uuid.uuid5(uuid.NAMESPACE_DNS, f"prowler.resource.{resource_uid}")
            )
            obs_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"prowler.obs.{finding_uid}"))

            check_id = (
                finding.metadata.CheckID
                if hasattr(finding, "metadata") and hasattr(finding.metadata, "CheckID")
                else "check_id"
            )
            check_title = (
                finding.metadata.CheckTitle
                if hasattr(finding, "metadata")
                and hasattr(finding.metadata, "CheckTitle")
                else check_id
            )
            status_extended = getattr(finding, "status_extended", check_title)

            severity_val = "medium"
            if hasattr(finding, "metadata") and hasattr(finding.metadata, "Severity"):
                sev = finding.metadata.Severity
                severity_val = sev.value if hasattr(sev, "value") else str(sev)

            subject = Subject(
                subject_uuid=subject_uuid,
                type="component",
                title=resource_name or resource_uid,
                description=f"Resource evaluated in region {region}",
                props=[
                    Property(name="resource-uid", value=resource_uid),
                    Property(name="region", value=region),
                ],
            )

            observation = Observation(
                observation_uuid=obs_uuid,
                title=f"{check_id}: {status_val}",
                description=status_extended,
                collected=finding_timestamp,
                subjects=[subject],
                props=[
                    Property(name="check-id", value=check_id),
                    Property(name="status", value=status_val),
                    Property(name="severity", value=severity_val),
                    Property(name="muted", value=str(muted).lower()),
                    Property(name="region", value=region),
                ],
            )
            result.observations.append(observation)

            # Emit OSCAL finding only for FAIL status
            if status_val == "FAIL":
                find_uuid = str(
                    uuid.uuid5(uuid.NAMESPACE_DNS, f"prowler.finding.{finding_uid}")
                )
                remediation_rec = ""
                if hasattr(finding, "metadata") and hasattr(
                    finding.metadata, "Remediation"
                ):
                    rem = finding.metadata.Remediation
                    if hasattr(rem, "Recommendation") and hasattr(
                        rem.Recommendation, "Text"
                    ):
                        remediation_rec = rem.Recommendation.Text

                oscal_finding = OscalFinding(
                    finding_uuid=find_uuid,
                    title=f"Non-compliant check: {check_id}",
                    description=status_extended,
                    target_id=check_id,
                    related_observations=[
                        RelatedObservation(observation_uuid=obs_uuid)
                    ],
                    props=[
                        Property(name="check-id", value=check_id),
                        Property(name="status", value="unsatisfied"),
                        Property(name="severity", value=severity_val),
                    ],
                )
                if remediation_rec:
                    oscal_finding.props.append(
                        Property(
                            name="remediation-recommendation", value=remediation_rec
                        )
                    )

                # Extract NIST compliance mappings if present
                compliance = getattr(finding, "compliance", {})
                if isinstance(compliance, dict):
                    for framework, controls in compliance.items():
                        if "nist" in framework.lower() and isinstance(controls, list):
                            for ctrl in controls:
                                oscal_finding.props.append(
                                    Property(
                                        name="control-id",
                                        value=str(ctrl),
                                        class_="compliance-control",
                                    )
                                )

                result.findings.append(oscal_finding)

        doc = OscalDocument(
            assessment_results=AssessmentResults(
                uuid=str(uuid.uuid4()),
                metadata=metadata,
                import_ap_href=self.import_ap_href,
                results=[result],
            )
        )
        self._data.append(doc)

    def batch_write_data_to_file(self) -> None:
        """
        Serializes and writes the OSCAL document to file.
        """
        if self._data and self.file_descriptor:
            for doc in self._data:
                payload = doc.to_dict()
                self.file_descriptor.write(json.dumps(payload, indent=2))
