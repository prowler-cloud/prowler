import logging
import os

import pytest

from prowler.lib.check.custom_checks_metadata import (
    parse_custom_checks_metadata_file,
    update_check_metadata,
    update_checks_metadata,
)
from prowler.lib.check.models import CheckMetadata, Code, Recommendation, Remediation

CUSTOM_CHECKS_METADATA_FIXTURE_FILE = f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/custom_checks_metadata_example.yaml"
CUSTOM_CHECKS_METADATA_FIXTURE_FILE_NOT_VALID = f"{os.path.dirname(os.path.realpath(__file__))}/fixtures/custom_checks_metadata_example_not_valid.yaml"

AWS_PROVIDER = "aws"
AZURE_PROVIDER = "azure"
GCP_PROVIDER = "gcp"
KUBERNETES_PROVIDER = "kubernetes"

S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME = "s3_bucket_level_public_access_block"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY = "medium"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_TERRAFORM = (
    "https://docs.prowler.com/checks/aws/s3-policies/bc_aws_s3_20#terraform"
)
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_OTHER = "https://github.com/cloudmatos/matos/tree/master/remediations/aws/s3/s3/block-public-access"
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_TEXT = (
    "Enable the S3 bucket level public access block."
)
S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_URL = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"


class TestCustomChecksMetadata:
    def get_custom_check_metadata(self):
        return CheckMetadata(
            Provider="aws",
            CheckID=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME,
            CheckTitle="Check S3 Bucket Level Public Access Block.",
            CheckType=["Data Protection"],
            CheckAliases=[],
            ServiceName="s3",
            SubServiceName="",
            ResourceIdTemplate="arn:partition:s3:::bucket_name",
            Severity=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY,
            ResourceType="AwsS3Bucket",
            Description="Check S3 Bucket Level Public Access Block.",
            Risk="Public access policies may be applied to sensitive data buckets.",
            RelatedUrl="https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            Remediation=Remediation(
                Code=Code(
                    NativeIaC="",
                    Terraform=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_TERRAFORM,
                    CLI="aws s3api put-public-access-block --region <REGION_NAME> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true --bucket <BUCKET_NAME>",
                    Other=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_OTHER,
                ),
                Recommendation=Recommendation(
                    Text=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_TEXT,
                    Url=S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_URL,
                ),
            ),
            Categories=[],
            DependsOn=[],
            RelatedTo=[],
            Notes="",
            Compliance=[],
        )

    def test_parse_custom_checks_metadata_file_for_aws(self):
        assert parse_custom_checks_metadata_file(
            AWS_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE
        ) == {
            "Checks": {
                "s3_bucket_level_public_access_block": {
                    "Severity": "high",
                    "CheckTitle": "S3 Bucket Level Public Access Block",
                    "Description": "This check ensures that the S3 bucket level public access block is enabled.",
                    "Risk": "This check is important because it ensures that the S3 bucket level public access block is enabled.",
                    "RelatedUrl": "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html",
                    "Remediation": {
                        "Code": {
                            "CLI": "aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                            "NativeIaC": "https://aws.amazon.com/es/s3/features/block-public-access/",
                            "Other": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                            "Terraform": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block",
                        },
                        "Recommendation": {
                            "Text": "Enable the S3 bucket level public access block.",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html",
                        },
                    },
                },
                "s3_bucket_no_mfa_delete": {
                    "Severity": "high",
                    "CheckTitle": "S3 Bucket No MFA Delete",
                    "Description": "This check ensures that the S3 bucket does not allow delete operations without MFA.",
                    "Risk": "This check is important because it ensures that the S3 bucket does not allow delete operations without MFA.",
                    "RelatedUrl": "https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html",
                    "Remediation": {
                        "Code": {
                            "CLI": "aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled",
                            "NativeIaC": "https://aws.amazon.com/es/s3/features/versioning/",
                            "Other": "https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html",
                            "Terraform": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning",
                        },
                        "Recommendation": {
                            "Text": "Enable versioning on the S3 bucket.",
                            "Url": "https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html",
                        },
                    },
                },
            }
        }

    def test_parse_custom_checks_metadata_file_for_azure(self):
        assert parse_custom_checks_metadata_file(
            AZURE_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE
        ) == {
            "Checks": {
                "storage_infrastructure_encryption_is_enabled": {
                    "Severity": "medium",
                    "CheckTitle": "Storage Infrastructure Encryption Is Enabled",
                    "Description": "This check ensures that storage infrastructure encryption is enabled.",
                    "Risk": "This check is important because it ensures that storage infrastructure encryption is enabled.",
                    "RelatedUrl": "https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption",
                    "Remediation": {
                        "Code": {
                            "CLI": "az storage account update --name <storage-account-name> --resource-group <resource-group-name> --set properties.encryption.services.blob.enabled=true properties.encryption.services.file.enabled=true properties.encryption.services.queue.enabled=true properties.encryption.services.table.enabled=true",
                            "NativeIaC": "https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts",
                            "Other": "https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption",
                            "Terraform": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account",
                        },
                        "Recommendation": {
                            "Text": "Enable storage infrastructure encryption.",
                            "Url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption",
                        },
                    },
                }
            }
        }

    def test_parse_custom_checks_metadata_file_for_gcp(self):
        assert parse_custom_checks_metadata_file(
            GCP_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE
        ) == {
            "Checks": {
                "compute_instance_public_ip": {
                    "Severity": "critical",
                    "CheckTitle": "Compute Instance Public IP",
                    "Description": "This check ensures that the compute instance does not have a public IP.",
                    "Risk": "This check is important because it ensures that the compute instance does not have a public IP.",
                    "RelatedUrl": "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
                    "Remediation": {
                        "Code": {
                            "CLI": "https://docs.prowler.com/checks/gcp/google-cloud-public-policies/bc_gcp_public_2#cli-command",
                            "NativeIaC": "https://cloud.google.com/compute/docs/reference/rest/v1/instances",
                            "Other": "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
                            "Terraform": "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance",
                        },
                        "Recommendation": {
                            "Text": "Remove the public IP from the compute instance.",
                            "Url": "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
                        },
                    },
                }
            }
        }

    def test_parse_custom_checks_metadata_file_for_kubernetes(self):
        assert parse_custom_checks_metadata_file(
            KUBERNETES_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE
        ) == {
            "Checks": {
                "apiserver_anonymous_requests": {
                    "Severity": "low",
                    "CheckTitle": "APIServer Anonymous Requests",
                    "Description": "This check ensures that anonymous requests to the APIServer are disabled.",
                    "Risk": "This check is important because it ensures that anonymous requests to the APIServer are disabled.",
                    "RelatedUrl": "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
                    "Remediation": {
                        "Code": {
                            "CLI": "--anonymous-auth=false",
                            "NativeIaC": "https://docs.prowler.com/checks/kubernetes/kubernetes-policy-index/ensure-that-the-anonymous-auth-argument-is-set-to-false-1#kubernetes",
                            "Other": "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
                            "Terraform": "https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/cluster_role_binding",
                        },
                        "Recommendation": {
                            "Text": "Disable anonymous requests to the APIServer.",
                            "Url": "https://kubernetes.io/docs/reference/access-authn-authz/authentication/",
                        },
                    },
                }
            }
        }

    def test_parse_custom_checks_metadata_file_for_aws_validation_error(self, caplog):
        caplog.set_level(logging.CRITICAL)

        with pytest.raises(SystemExit) as error:
            parse_custom_checks_metadata_file(
                AWS_PROVIDER, CUSTOM_CHECKS_METADATA_FIXTURE_FILE_NOT_VALID
            )
        assert error.type == SystemExit
        assert error.value.code == 1
        assert "'Checks' is a required property" in caplog.text

    def test_update_checks_metadata(self):
        updated_severity = "high"
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata(),
        }
        custom_checks_metadata = {
            "Checks": {
                S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: {
                    "Severity": updated_severity
                },
            }
        }

        bulk_checks_metadata_updated = update_checks_metadata(
            bulk_checks_metadata, custom_checks_metadata
        ).get(S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME)

        assert bulk_checks_metadata_updated.Severity == updated_severity

    def test_update_checks_metadata_one_field(self):
        updated_terraform = (
            "https://docs.prowler.com/checks/aws/s3-policies/bc_aws_s3_21/#terraform"
        )
        updated_text = "You can enable Public Access Block at the bucket level to prevent the exposure of your data stored in S3."
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata(),
        }

        custom_checks_metadata = {
            "Checks": {
                S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: {
                    "Remediation": {
                        "Code": {"Terraform": updated_terraform},
                        "Recommendation": {
                            "Text": updated_text,
                        },
                    },
                },
            }
        }

        bulk_checks_metadata_updated = update_checks_metadata(
            bulk_checks_metadata, custom_checks_metadata
        ).get(S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME)
        assert (
            bulk_checks_metadata_updated.Remediation.Code.Terraform == updated_terraform
        )
        assert (
            bulk_checks_metadata_updated.Remediation.Code.Other
            == S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_OTHER
        )
        assert (
            bulk_checks_metadata_updated.Remediation.Recommendation.Text == updated_text
        )
        assert (
            bulk_checks_metadata_updated.Remediation.Recommendation.Url
            == S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_REMEDIATION_URL
        )

    def test_update_checks_metadata_not_present_field(self):
        bulk_checks_metadata = {
            S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: self.get_custom_check_metadata(),
        }
        custom_checks_metadata = {
            "Checks": {
                S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME: {
                    "RandomField": "random_value"
                },
            }
        }

        bulk_checks_metadata_updated = update_checks_metadata(
            bulk_checks_metadata, custom_checks_metadata
        ).get(S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_NAME)

        assert (
            bulk_checks_metadata_updated.Severity
            == S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY
        )

    def test_update_check_metadata(self):
        updated_severity = "high"
        custom_checks_metadata = {"Severity": updated_severity}

        check_metadata_updated = update_check_metadata(
            self.get_custom_check_metadata(), custom_checks_metadata
        )
        assert check_metadata_updated.Severity == updated_severity

    def test_update_check_metadata_not_present_field(self):
        custom_checks_metadata = {"RandomField": "random_value"}

        check_metadata_updated = update_check_metadata(
            self.get_custom_check_metadata(), custom_checks_metadata
        )
        assert (
            check_metadata_updated.Severity
            == S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY
        )

    def test_update_check_metadata_none_custom_metadata(self):
        custom_checks_metadata = None

        check_metadata_updated = update_check_metadata(
            self.get_custom_check_metadata(), custom_checks_metadata
        )
        assert (
            check_metadata_updated.Severity
            == S3_BUCKET_LEVEL_PUBLIC_ACCESS_BLOCK_SEVERITY
        )
