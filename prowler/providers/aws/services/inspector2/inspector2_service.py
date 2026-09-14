from datetime import datetime
from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Inspector2(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.inspectors = []
        self.known_exploited_vulnerabilities = {}
        self.vulnerability_lookup_failed = set()
        self.__threading_call__(self._batch_get_account_status)
        self.__threading_call__(self._list_active_findings, self.inspectors)
        enabled_inspectors = [
            inspector for inspector in self.inspectors if inspector.status == "ENABLED"
        ]
        self.__threading_call__(self._list_findings, enabled_inspectors)
        self.__threading_call__(self._list_coverage, enabled_inspectors)
        self.__threading_call__(
            self._search_vulnerability,
            self._get_vulnerability_lookups(enabled_inspectors),
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

    def _list_findings(self, inspector):
        """Store the active findings of the audited account for an enabled Region."""
        logger.info("Inspector2 - Listing active findings details...")
        try:
            paginator = self.regional_clients[inspector.region].get_paginator(
                "list_findings"
            )
            findings = []
            for page in paginator.paginate(
                filterCriteria={
                    "awsAccountId": [
                        {"comparison": "EQUALS", "value": self.audited_account},
                    ],
                    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                },
                PaginationConfig={"PageSize": 100},
            ):
                for finding in page.get("findings", []):
                    findings.append(
                        Finding(
                            arn=finding.get("findingArn", ""),
                            type=finding.get("type", ""),
                            severity=finding.get("severity", ""),
                            first_observed_at=finding.get("firstObservedAt"),
                            vulnerability_id=finding.get(
                                "packageVulnerabilityDetails", {}
                            ).get("vulnerabilityId"),
                            resource_ids=[
                                resource["id"]
                                for resource in finding.get("resources", [])
                                if resource.get("id")
                            ],
                        )
                    )
            inspector.findings = findings
        except Exception as error:
            logger.error(
                f"{inspector.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
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

    def _get_covered_resource_arn(self, resource_type, resource_id, region):
        """Return the ARN of a covered resource, building it for EC2 instance IDs."""
        if resource_type == "AWS_EC2_INSTANCE" and not resource_id.startswith("arn:"):
            return f"arn:{self.audited_partition}:ec2:{region}:{self.audited_account}:instance/{resource_id}"
        return resource_id

    @staticmethod
    def _get_vulnerability_lookups(inspectors):
        """Map each CVE with an active finding to one Region where it can be looked up."""
        lookups = {}
        for inspector in inspectors:
            for finding in inspector.findings or []:
                if finding.vulnerability_id and finding.vulnerability_id.startswith(
                    "CVE-"
                ):
                    lookups.setdefault(finding.vulnerability_id, inspector.region)
        return list(lookups.items())

    def _search_vulnerability(self, lookup):
        """Record the CISA KEV data of a CVE, flagging the lookup as failed on error."""
        vulnerability_id, region = lookup
        logger.info(f"Inspector2 - Searching vulnerability {vulnerability_id}...")
        try:
            response = self.regional_clients[region].search_vulnerabilities(
                filterCriteria={"vulnerabilityIds": [vulnerability_id]}
            )
            for vulnerability in response.get("vulnerabilities", []):
                cisa_data = vulnerability.get("cisaData")
                if cisa_data:
                    self.known_exploited_vulnerabilities[vulnerability_id] = (
                        KnownExploitedVulnerability(
                            id=vulnerability_id,
                            date_added=cisa_data.get("dateAdded"),
                            date_due=cisa_data.get("dateDue"),
                        )
                    )
        except Exception as error:
            self.vulnerability_lookup_failed.add(vulnerability_id)
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
    findings: Optional[list[Finding]] = None
    coverage: Optional[list[CoveredResource]] = None
