import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from prowler.lib.outputs.common import Status
from prowler.lib.outputs.finding import Finding
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
    """Transforms Prowler findings into NIST OSCAL 1.2.3 Assessment Results JSON."""

    def __init__(
        self,
        findings: List[Finding],
        file_path: Optional[str] = None,
        import_ap_href: str = DEFAULT_IMPORT_AP_HREF,
    ) -> None:
        """Build and hold the OSCAL document(s) for the given findings.

        Args:
            findings: Prowler ``Finding`` objects to transform.
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

    def transform(self, findings: List[Finding]) -> None:
        """Transform Prowler findings into an OSCAL AssessmentResults document.

        Args:
            findings: Non-empty list of ``Finding`` instances for one export.
        """
        if not findings:
            return

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        first_finding = findings[0]
        account_uid = first_finding.account_uid
        provider_name = first_finding.metadata.Provider
        prowler_version = first_finding.prowler_version

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

        # Result UUID must be unique per export (one assessment run), while
        # observation/finding UUIDs stay reproducible from finding.uid.
        result_uuid = str(uuid.uuid4())
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
            # OSCAL date-time-with-timezone requires a Z / offset; naive
            # finding timestamps (common in tests and some providers) must
            # be treated as UTC rather than emitted without a zone.
            if isinstance(finding.timestamp, datetime):
                ts = finding.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                finding_timestamp = ts.isoformat()
            else:
                finding_timestamp = now_iso
            status_val = (
                finding.status.value
                if hasattr(finding.status, "value")
                else str(finding.status)
            )
            severity_val = (
                finding.metadata.Severity.value
                if hasattr(finding.metadata.Severity, "value")
                else str(finding.metadata.Severity)
            )

            subject_uuid = str(
                uuid.uuid5(
                    uuid.NAMESPACE_DNS, f"prowler.resource.{finding.resource_uid}"
                )
            )
            obs_uuid = str(
                uuid.uuid5(uuid.NAMESPACE_DNS, f"prowler.obs.{finding.uid}")
            )

            subject = Subject(
                subject_uuid=subject_uuid,
                type="component",
                title=finding.resource_name or finding.resource_uid,
                props=[
                    Property(name="resource-uid", value=finding.resource_uid),
                    Property(name="region", value=finding.region),
                ],
            )

            observation = Observation(
                observation_uuid=obs_uuid,
                title=f"{finding.metadata.CheckID}: {status_val}",
                description=finding.status_extended,
                collected=finding_timestamp,
                subjects=[subject],
                props=[
                    Property(name="check-id", value=finding.metadata.CheckID),
                    Property(name="status", value=status_val),
                    Property(name="severity", value=severity_val),
                    Property(name="muted", value=str(finding.muted).lower()),
                    Property(name="region", value=finding.region),
                ],
            )
            result.observations.append(observation)

            # FAIL only, and never muted — muted FAILs stay as observations
            # with muted=true so suppressed results do not assert remediation.
            if status_val == Status.FAIL and not finding.muted:
                find_uuid = str(
                    uuid.uuid5(uuid.NAMESPACE_DNS, f"prowler.finding.{finding.uid}")
                )
                remediation_rec = ""
                rem = finding.metadata.Remediation
                if rem and rem.Recommendation and rem.Recommendation.Text:
                    remediation_rec = rem.Recommendation.Text

                oscal_finding = OscalFinding(
                    finding_uuid=find_uuid,
                    title=f"Non-compliant check: {finding.metadata.CheckID}",
                    description=finding.status_extended,
                    target_id=finding.metadata.CheckID,
                    related_observations=[
                        RelatedObservation(observation_uuid=obs_uuid)
                    ],
                    props=[
                        Property(name="check-id", value=finding.metadata.CheckID),
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

                if isinstance(finding.compliance, dict):
                    for framework, controls in finding.compliance.items():
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
        """Serialize and write the OSCAL document to ``file_descriptor``."""
        if self._data and self.file_descriptor:
            for doc in self._data:
                payload = doc.to_dict()
                self.file_descriptor.write(json.dumps(payload, indent=2))
