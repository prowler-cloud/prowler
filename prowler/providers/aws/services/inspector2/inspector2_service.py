from datetime import datetime
from typing import Optional

from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.lib.threats import load_signatures
from prowler.providers.aws.lib.service.service import AWSService

FINDING_DETAILS_BATCH_SIZE = 10
# Inspector2 StringFilterList accepts at most 10 values
VULNERABILITY_FILTER_SIZE = 10


class Inspector2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.inspectors = []
        self.known_exploited_vulnerabilities = {}
        self.vulnerability_lookup_failed = set()
        self._vulnerability_database = {}
        self.__threading_call__(self._batch_get_account_status)
        self.__threading_call__(self._list_active_findings, self.inspectors)
        enabled_inspectors = [
            inspector for inspector in self.inspectors if inspector.status == "ENABLED"
        ]
        self.__threading_call__(self._list_oldest_finding, enabled_inspectors)
        self.__threading_call__(self._list_kev_candidates, enabled_inspectors)
        self.__threading_call__(self._list_threat_findings, enabled_inspectors)
        self.__threading_call__(self._list_coverage, enabled_inspectors)
        self.__threading_call__(
            self._batch_get_finding_details,
            self._get_finding_detail_batches(enabled_inspectors),
        )

    def _batch_get_account_status(self, regional_client):
        # We use this function to check if inspector2 is enabled
        logger.info("Inspector2 - Getting account status...")
        try:
            batch_get_account_status = regional_client.batch_get_account_status(
                accountIds=[self.audited_account]
            )["accounts"][0]
            resourceStates = batch_get_account_status.get("resourceState")
            self.inspectors.append(
                Inspector(
                    id="Inspector2",
                    arn=f"arn:{self.audited_partition}:inspector2:{regional_client.region}:{self.audited_account}:inspector2",
                    status=batch_get_account_status.get("state").get("status"),
                    ec2_status=resourceStates.get("ec2", {}).get("status"),
                    ecr_status=resourceStates.get("ecr", {}).get("status"),
                    lambda_status=resourceStates.get("lambda", {}).get("status"),
                    lambda_code_status=resourceStates.get("lambdaCode", {}).get(
                        "status"
                    ),
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_active_findings(self, inspector):
        logger.info("Inspector2 - Listing active findings...")
        try:
            regional_client = self.regional_clients[inspector.region]
            active_findings = regional_client.list_findings(
                filterCriteria={
                    "awsAccountId": [
                        {"comparison": "EQUALS", "value": self.audited_account},
                    ],
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                },
                maxResults=1,  # Retrieve only 1 finding to check for existence
            )
            inspector.active_findings = len(active_findings.get("findings")) > 0

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _active_findings_filter(self, **criteria) -> dict:
        """Filter criteria for the active findings of the audited account."""
        return {
            "awsAccountId": [{"comparison": "EQUALS", "value": self.audited_account}],
            "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
            **criteria,
        }

    def _list_oldest_finding(self, inspector):
        """Store the active finding first observed the longest ago."""
        logger.info("Inspector2 - Getting the oldest active finding...")
        try:
            response = self.regional_clients[inspector.region].list_findings(
                filterCriteria=self._active_findings_filter(),
                sortCriteria={"field": "FIRST_OBSERVED_AT", "sortOrder": "ASC"},
                maxResults=1,
            )
            inspector.oldest_findings = [
                self._build_finding(finding) for finding in response.get("findings", [])
            ]
        except Exception as error:
            logger.error(
                f"{inspector.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_kev_candidates(self, inspector):
        """Store one active finding ARN per CVE that could be a CISA KEV."""
        logger.info("Inspector2 - Listing CISA KEV candidate findings...")
        try:
            criteria = {}
            if not self.audit_config.get(
                "inspector2_kev_include_findings_without_exploit", False
            ):
                criteria["exploitAvailable"] = [
                    {"comparison": "EQUALS", "value": "YES"}
                ]
            paginator = self.regional_clients[inspector.region].get_paginator(
                "list_findings"
            )
            candidates = {}
            for page in paginator.paginate(
                filterCriteria=self._active_findings_filter(**criteria),
                PaginationConfig={"PageSize": 100},
            ):
                for finding in page.get("findings", []):
                    vulnerability_id = finding.get(
                        "packageVulnerabilityDetails", {}
                    ).get("vulnerabilityId")
                    if vulnerability_id and vulnerability_id.startswith("CVE-"):
                        candidates.setdefault(
                            vulnerability_id, finding.get("findingArn", "")
                        )
            inspector.kev_candidates = candidates
        except Exception as error:
            logger.error(
                f"{inspector.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _list_threat_findings(self, inspector):
        """Store the emerging threat CVEs Inspector2 reports per EC2 instance."""
        logger.info("Inspector2 - Listing emerging threat findings...")
        try:
            cves = sorted(
                {
                    cve
                    for signature in load_signatures(self.audit_config)
                    for cve in signature.cves
                }
            )
            paginator = self.regional_clients[inspector.region].get_paginator(
                "list_findings"
            )
            threat_findings = {}
            for index in range(0, len(cves), VULNERABILITY_FILTER_SIZE):
                chunk = cves[index : index + VULNERABILITY_FILTER_SIZE]
                for page in paginator.paginate(
                    filterCriteria=self._active_findings_filter(
                        resourceType=[
                            {"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"}
                        ],
                        vulnerabilityId=[
                            {"comparison": "EQUALS", "value": cve} for cve in chunk
                        ],
                    ),
                    PaginationConfig={"PageSize": 100},
                ):
                    for finding in page.get("findings", []):
                        built = self._build_finding(finding)
                        if built.vulnerability_id:
                            for resource_id in built.resource_ids:
                                threat_findings.setdefault(resource_id, set()).add(
                                    built.vulnerability_id
                                )
            inspector.threat_findings = threat_findings
        except Exception as error:
            logger.error(
                f"{inspector.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _build_finding(finding: dict) -> "Finding":
        """Build a Finding from a ListFindings item."""
        return Finding(
            arn=finding.get("findingArn", ""),
            type=finding.get("type", ""),
            severity=finding.get("severity", ""),
            first_observed_at=finding.get("firstObservedAt"),
            vulnerability_id=finding.get("packageVulnerabilityDetails", {}).get(
                "vulnerabilityId"
            ),
            resource_ids=[
                resource["id"]
                for resource in finding.get("resources", [])
                if resource.get("id")
            ],
        )

    def _list_coverage(self, inspector):
        """Store the resources Inspector2 covers in an enabled Region, respecting audit resources."""
        logger.info("Inspector2 - Listing coverage...")
        try:
            paginator = self.regional_clients[inspector.region].get_paginator(
                "list_coverage"
            )
            coverage = []
            for page in paginator.paginate(
                filterCriteria={
                    "accountId": [
                        {"comparison": "EQUALS", "value": self.audited_account},
                    ],
                },
                PaginationConfig={"PageSize": 200},
            ):
                for covered_resource in page.get("coveredResources", []):
                    resource_id = covered_resource.get("resourceId", "")
                    resource_type = covered_resource.get("resourceType", "")
                    scan_status = covered_resource.get("scanStatus", {})
                    arn = self._get_covered_resource_arn(
                        resource_type, resource_id, inspector.region
                    )
                    if self.audit_resources and not is_resource_filtered(
                        arn, self.audit_resources
                    ):
                        continue
                    coverage.append(
                        CoveredResource(
                            id=resource_id,
                            arn=arn,
                            region=inspector.region,
                            resource_type=resource_type,
                            scan_type=covered_resource.get("scanType", ""),
                            scan_status_code=scan_status.get("statusCode", ""),
                            scan_status_reason=scan_status.get("reason", ""),
                            last_scanned_at=covered_resource.get("lastScannedAt"),
                        )
                    )
            inspector.coverage = coverage
        except Exception as error:
            logger.error(
                f"{inspector.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def vulnerability_known(self, vulnerability_id: str) -> bool:
        """Whether Amazon Inspector's vulnerability database lists the CVE.

        No finding for a CVE on a scanned host means the host is not affected
        only when Inspector can detect that CVE, which a brand new CVE may not
        be yet. Looked up on first use and cached for the scan.

        Returns:
            ``True`` when the database lists it; ``False`` when it does not, or
            when the lookup is not possible (Inspector off, access denied).
        """
        if vulnerability_id not in self._vulnerability_database:
            self._vulnerability_database[vulnerability_id] = self._search_vulnerability(
                vulnerability_id
            )
        return self._vulnerability_database[vulnerability_id]

    def _search_vulnerability(self, vulnerability_id: str) -> bool:
        """Look a CVE up in the vulnerability database of an enabled Region."""
        region = next(
            (
                inspector.region
                for inspector in self.inspectors
                if inspector.status == "ENABLED"
            ),
            None,
        )
        if region is None:
            return False
        try:
            response = self.regional_clients[region].search_vulnerabilities(
                filterCriteria={"vulnerabilityIds": [vulnerability_id]}
            )
            return any(
                vulnerability.get("id") == vulnerability_id
                for vulnerability in response.get("vulnerabilities", [])
            )
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False

    def _get_covered_resource_arn(self, resource_type, resource_id, region):
        """Return the ARN of a covered resource, building it for EC2 instance IDs."""
        if resource_type == "AWS_EC2_INSTANCE" and not resource_id.startswith("arn:"):
            return f"arn:{self.audited_partition}:ec2:{region}:{self.audited_account}:instance/{resource_id}"
        return resource_id

    @staticmethod
    def _get_finding_detail_batches(inspectors):
        """Group one active finding per CVE into finding details batches per Region."""
        representatives = {}
        for inspector in inspectors:
            for vulnerability_id, finding_arn in (
                inspector.kev_candidates or {}
            ).items():
                representatives.setdefault(
                    vulnerability_id, (inspector.region, finding_arn)
                )
        findings_by_region = {}
        for vulnerability_id, (region, finding_arn) in representatives.items():
            findings_by_region.setdefault(region, []).append(
                (finding_arn, vulnerability_id)
            )
        return [
            (region, findings[index : index + FINDING_DETAILS_BATCH_SIZE])
            for region, findings in findings_by_region.items()
            for index in range(0, len(findings), FINDING_DETAILS_BATCH_SIZE)
        ]

    def _batch_get_finding_details(self, batch):
        """Record the CISA KEV data of the CVEs in a batch, flagging failed lookups."""
        region, findings = batch
        vulnerability_ids = dict(findings)
        logger.info("Inspector2 - Getting finding details...")
        try:
            response = self.regional_clients[region].batch_get_finding_details(
                findingArns=list(vulnerability_ids)
            )
            for detail in response.get("findingDetails", []):
                vulnerability_id = vulnerability_ids.get(detail.get("findingArn"))
                cisa_data = detail.get("cisaData")
                if vulnerability_id and cisa_data:
                    self.known_exploited_vulnerabilities[vulnerability_id] = (
                        KnownExploitedVulnerability(
                            id=vulnerability_id,
                            date_added=cisa_data.get("dateAdded"),
                            date_due=cisa_data.get("dateDue"),
                        )
                    )
            for detail_error in response.get("errors", []):
                # Inspector has no intelligence for the CVE, so it cannot be a KEV
                if detail_error.get("errorCode") == "FINDING_DETAILS_NOT_FOUND":
                    continue
                vulnerability_id = vulnerability_ids.get(detail_error.get("findingArn"))
                if vulnerability_id:
                    self.vulnerability_lookup_failed.add(vulnerability_id)
                    logger.error(
                        f"{region} -- {detail_error.get('errorCode')} getting finding details for {vulnerability_id}: {detail_error.get('errorMessage')}"
                    )
        except Exception as error:
            self.vulnerability_lookup_failed.update(vulnerability_ids.values())
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Finding(BaseModel):
    """Active Inspector2 finding."""

    arn: str
    type: str
    severity: str
    first_observed_at: Optional[datetime]
    vulnerability_id: Optional[str]
    resource_ids: list[str] = []


class CoveredResource(BaseModel):
    """Resource tracked by Inspector2 coverage."""

    id: str
    arn: str
    region: str
    resource_type: str
    scan_type: str
    scan_status_code: str
    scan_status_reason: str
    last_scanned_at: Optional[datetime]


class KnownExploitedVulnerability(BaseModel):
    """CISA Known Exploited Vulnerability data of a CVE."""

    id: str
    date_added: Optional[datetime]
    date_due: Optional[datetime]


class Inspector(BaseModel):
    id: str
    arn: str
    region: str
    status: str
    ec2_status: str
    ecr_status: str
    lambda_status: str
    lambda_code_status: str
    active_findings: bool = None
    # Lookups below: None means it failed; excluded from the resource metadata
    # Only the oldest active finding, empty when there is none
    oldest_findings: Optional[list[Finding]] = Field(default=None, exclude=True)
    # CVE id -> one active finding ARN for it
    kev_candidates: Optional[dict[str, str]] = Field(default=None, exclude=True)
    # EC2 instance id -> emerging threat CVEs with an active finding on it
    threat_findings: Optional[dict[str, set[str]]] = Field(default=None, exclude=True)
    coverage: Optional[list[CoveredResource]] = Field(default=None, exclude=True)
