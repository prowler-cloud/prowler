import json
from typing import List

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output


class ComplianceJSON(Output):
    """
    ComplianceJSON class that transforms findings into a custom compliance-focused JSON format.
    
    This class provides methods to transform findings into a simplified JSON format
    that focuses on compliance information and asset details, similar to external
    compliance reporting tools.
    
    Attributes:
        - _data: A list to store the transformed findings.
        - _file_descriptor: A file descriptor to write the findings to a file.
    
    Methods:
        - transform(findings: List[Finding]) -> None: Transforms findings into compliance JSON format.
        - batch_write_data_to_file() -> None: Writes findings to file in JSON format.
    """

    def transform(self, findings: List[Finding]) -> None:
        """Transforms the findings into a custom compliance JSON format.

        Args:
            findings (List[Finding]): a list of Finding objects
        """
        try:
            for finding in findings:
                # Create the basic compliance record structure
                compliance_record = {
                    "asset_type_string": self._get_asset_type_string(finding),
                    "asset_name": finding.resource_name or finding.account_name,
                    "asset_state": "enabled",  # Default to enabled
                    "account_name": finding.account_name,
                    "asset_unique_id": f"{finding.metadata.ServiceName}_{finding.account_uid}_{finding.resource_name or finding.account_uid}",
                    "asset_vendor_id": finding.resource_uid or finding.account_uid,
                    "priv": {
                        "full_scan_time": finding.timestamp.isoformat() if finding.timestamp else None,
                    },
                    "compliance": {
                        "check_id": finding.metadata.CheckID,
                        "check_title": finding.metadata.CheckTitle,
                        "description": finding.metadata.Description,
                        "service_name": finding.metadata.ServiceName,
                        "subservice_name": finding.metadata.SubServiceName,
                        "resource_type": finding.metadata.ResourceType,
                        "resource_id_template": finding.metadata.ResourceIdTemplate,
                        "severity": finding.metadata.Severity.value,
                        "result": finding.status,
                        "status_extended": finding.status_extended,
                        "categories": finding.metadata.Categories,
                        "depends_on": finding.metadata.DependsOn,
                        "related_to": finding.metadata.RelatedTo,
                        "notes": finding.metadata.Notes,
                        "compliance_frameworks": finding.compliance if finding.compliance else {},
                        "remediation": {
                            "recommendation": finding.metadata.Remediation.Recommendation.Text if finding.metadata.Remediation.Recommendation else None,
                            "url": finding.metadata.Remediation.Recommendation.Url if finding.metadata.Remediation.Recommendation else None,
                            "code": {
                                "cli": finding.metadata.Remediation.Code.CLI if finding.metadata.Remediation.Code else None,
                                "terraform": finding.metadata.Remediation.Code.Terraform if finding.metadata.Remediation.Code else None,
                                "native_iac": finding.metadata.Remediation.Code.NativeIaC if finding.metadata.Remediation.Code else None,
                                "other": finding.metadata.Remediation.Code.Other if finding.metadata.Remediation.Code else None,
                            }
                        },
                        "risk": finding.metadata.Risk,
                        "related_url": finding.metadata.RelatedUrl,
                    },
                    "provider": finding.provider,
                    "region": finding.region,
                    "account_uid": finding.account_uid,
                    "resource_details": finding.resource_details,
                    "resource_tags": finding.resource_tags,
                    "partition": finding.partition,
                    "prowler_version": finding.prowler_version,
                }

                # Add provider-specific location information
                if finding.provider == "aws":
                    compliance_record["location"] = finding.region
                elif finding.provider == "azure":
                    compliance_record["location"] = finding.location
                    compliance_record["subscription"] = finding.subscription
                elif finding.provider == "gcp":
                    compliance_record["location"] = finding.location
                    compliance_record["project_id"] = finding.project_id
                elif finding.provider == "kubernetes":
                    compliance_record["namespace"] = finding.namespace
                    compliance_record["cluster"] = finding.region
                elif finding.provider == "github":
                    compliance_record["owner"] = finding.owner
                    compliance_record["repository"] = finding.location
                elif finding.provider == "m365":
                    compliance_record["tenant_id"] = finding.tenant_id
                    compliance_record["location"] = finding.location

                # Add failure-specific information if available
                if finding.status == "FAIL" and hasattr(finding, 'recommendation'):
                    compliance_record["recommendation"] = getattr(finding, 'recommendation', None)

                # Add muting information
                if finding.muted:
                    compliance_record["muted"] = True
                    compliance_record["mute_reason"] = getattr(finding, 'mute_reason', 'Unknown')

                self._data.append(compliance_record)

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_asset_type_string(self, finding: Finding) -> str:
        """Generate an asset type string based on the provider and resource type."""
        if finding.provider == "aws":
            if finding.metadata.ServiceName.lower() == "s3":
                return "AWS S3 Bucket"
            elif finding.metadata.ServiceName.lower() == "ec2":
                return "AWS EC2 Instance"
            elif finding.metadata.ServiceName.lower() == "iam":
                return "AWS IAM Resource"
            elif finding.metadata.ServiceName.lower() == "rds":
                return "AWS RDS Instance"
            elif finding.metadata.ServiceName.lower() == "lambda":
                return "AWS Lambda Function"
            else:
                return f"AWS {finding.metadata.ServiceName.upper()} Resource"
        elif finding.provider == "azure":
            return f"Azure {finding.metadata.ServiceName}"
        elif finding.provider == "gcp":
            return f"GCP {finding.metadata.ServiceName}"
        elif finding.provider == "kubernetes":
            return f"Kubernetes {finding.metadata.ResourceType or 'Resource'}"
        elif finding.provider == "github":
            return "GitHub Repository"
        elif finding.provider == "m365":
            return f"Microsoft 365 {finding.metadata.ServiceName}"
        else:
            return "Cloud Resource"

    def batch_write_data_to_file(self) -> None:
        """Writes the findings to a file using JSON format."""
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                # Write as a JSON array
                json_output = json.dumps(self._data, indent=2, default=str)
                self._file_descriptor.write(json_output)
                
                if self.close_file or self._from_cli:
                    self._file_descriptor.close()
                    
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )