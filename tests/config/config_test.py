import logging
import os
import pathlib
from unittest import mock

from requests import Response

from prowler.config.config import (
    check_current_version,
    get_available_compliance_frameworks,
    load_and_validate_config_file,
    load_and_validate_fixer_config_file,
)

MOCK_PROWLER_VERSION = "3.3.0"
MOCK_OLD_PROWLER_VERSION = "0.0.0"
MOCK_PROWLER_MASTER_VERSION = "3.4.0"


def mock_prowler_get_latest_release(_, **kwargs):
    """Mock requests.get() to get the Prowler latest release"""
    response = Response()
    response._content = b'[{"name":"3.3.0"}]'
    return response


old_config_aws = {
    "shodan_api_key": None,
    "max_security_group_rules": 50,
    "max_ec2_instance_age_in_days": 180,
    "ec2_allowed_interface_types": ["api_gateway_managed", "vpc_endpoint"],
    "ec2_allowed_instance_owners": ["amazon-elb"],
    "trusted_account_ids": [],
    "log_group_retention_days": 365,
    "max_idle_disconnect_timeout_in_seconds": 600,
    "max_disconnect_timeout_in_seconds": 300,
    "max_session_duration_seconds": 36000,
    "obsolete_lambda_runtimes": [
        "java8",
        "go1.x",
        "provided",
        "python3.6",
        "python2.7",
        "python3.7",
        "nodejs4.3",
        "nodejs4.3-edge",
        "nodejs6.10",
        "nodejs",
        "nodejs8.10",
        "nodejs10.x",
        "nodejs12.x",
        "nodejs14.x",
        "dotnet5.0",
        "dotnetcore1.0",
        "dotnetcore2.0",
        "dotnetcore2.1",
        "dotnetcore3.1",
        "ruby2.5",
        "ruby2.7",
    ],
    "organizations_enabled_regions": [],
    "organizations_trusted_delegated_administrators": [],
    "check_rds_instance_replicas": False,
    "days_to_expire_threshold": 7,
    "eks_required_log_types": [
        "api",
        "audit",
        "authenticator",
        "controllerManager",
        "scheduler",
    ],
}
config_aws = {
    "mute_non_default_regions": False,
    "max_unused_access_keys_days": 45,
    "max_console_access_days": 45,
    "shodan_api_key": None,
    "max_security_group_rules": 50,
    "max_ec2_instance_age_in_days": 180,
    "ec2_allowed_interface_types": ["api_gateway_managed", "vpc_endpoint"],
    "ec2_allowed_instance_owners": ["amazon-elb"],
    "ec2_high_risk_ports": [
        25,
        110,
        135,
        143,
        445,
        3000,
        4333,
        5000,
        5500,
        8080,
        8088,
    ],
    "fargate_linux_latest_version": "1.4.0",
    "fargate_windows_latest_version": "1.0.0",
    "trusted_account_ids": [],
    "log_group_retention_days": 365,
    "max_idle_disconnect_timeout_in_seconds": 600,
    "max_disconnect_timeout_in_seconds": 300,
    "max_session_duration_seconds": 36000,
    "obsolete_lambda_runtimes": [
        "java8",
        "go1.x",
        "provided",
        "python3.6",
        "python2.7",
        "python3.7",
        "nodejs4.3",
        "nodejs4.3-edge",
        "nodejs6.10",
        "nodejs",
        "nodejs8.10",
        "nodejs10.x",
        "nodejs12.x",
        "nodejs14.x",
        "dotnet5.0",
        "dotnetcore1.0",
        "dotnetcore2.0",
        "dotnetcore2.1",
        "dotnetcore3.1",
        "ruby2.5",
        "ruby2.7",
    ],
    "lambda_min_azs": 2,
    "organizations_enabled_regions": [],
    "organizations_trusted_delegated_administrators": [],
    "ecr_repository_vulnerability_minimum_severity": "MEDIUM",
    "verify_premium_support_plans": True,
    "threat_detection_privilege_escalation_threshold": 0.2,
    "threat_detection_privilege_escalation_minutes": 1440,
    "threat_detection_privilege_escalation_actions": [
        "AddPermission",
        "AddRoleToInstanceProfile",
        "AddUserToGroup",
        "AssociateAccessPolicy",
        "AssumeRole",
        "AttachGroupPolicy",
        "AttachRolePolicy",
        "AttachUserPolicy",
        "ChangePassword",
        "CreateAccessEntry",
        "CreateAccessKey",
        "CreateDevEndpoint",
        "CreateEventSourceMapping",
        "CreateFunction",
        "CreateGroup",
        "CreateJob",
        "CreateKeyPair",
        "CreateLoginProfile",
        "CreatePipeline",
        "CreatePolicyVersion",
        "CreateRole",
        "CreateStack",
        "DeleteRolePermissionsBoundary",
        "DeleteRolePolicy",
        "DeleteUserPermissionsBoundary",
        "DeleteUserPolicy",
        "DetachRolePolicy",
        "DetachUserPolicy",
        "GetCredentialsForIdentity",
        "GetId",
        "GetPolicyVersion",
        "GetUserPolicy",
        "Invoke",
        "ModifyInstanceAttribute",
        "PassRole",
        "PutGroupPolicy",
        "PutPipelineDefinition",
        "PutRolePermissionsBoundary",
        "PutRolePolicy",
        "PutUserPermissionsBoundary",
        "PutUserPolicy",
        "ReplaceIamInstanceProfileAssociation",
        "RunInstances",
        "SetDefaultPolicyVersion",
        "UpdateAccessKey",
        "UpdateAssumeRolePolicy",
        "UpdateDevEndpoint",
        "UpdateEventSourceMapping",
        "UpdateFunctionCode",
        "UpdateJob",
        "UpdateLoginProfile",
    ],
    "threat_detection_enumeration_threshold": 0.3,
    "threat_detection_enumeration_minutes": 1440,
    "threat_detection_enumeration_actions": [
        "DescribeAccessEntry",
        "DescribeAccountAttributes",
        "DescribeAvailabilityZones",
        "DescribeBundleTasks",
        "DescribeCarrierGateways",
        "DescribeClientVpnRoutes",
        "DescribeCluster",
        "DescribeDhcpOptions",
        "DescribeFlowLogs",
        "DescribeImages",
        "DescribeInstanceAttribute",
        "DescribeInstanceInformation",
        "DescribeInstanceTypes",
        "DescribeInstances",
        "DescribeInstances",
        "DescribeKeyPairs",
        "DescribeLogGroups",
        "DescribeLogStreams",
        "DescribeOrganization",
        "DescribeRegions",
        "DescribeSecurityGroups",
        "DescribeSnapshotAttribute",
        "DescribeSnapshotTierStatus",
        "DescribeSubscriptionFilters",
        "DescribeTransitGatewayMulticastDomains",
        "DescribeVolumes",
        "DescribeVolumesModifications",
        "DescribeVpcEndpointConnectionNotifications",
        "DescribeVpcs",
        "GetAccount",
        "GetAccountAuthorizationDetails",
        "GetAccountSendingEnabled",
        "GetBucketAcl",
        "GetBucketLogging",
        "GetBucketPolicy",
        "GetBucketReplication",
        "GetBucketVersioning",
        "GetCallerIdentity",
        "GetCertificate",
        "GetConsoleScreenshot",
        "GetCostAndUsage",
        "GetDetector",
        "GetEbsDefaultKmsKeyId",
        "GetEbsEncryptionByDefault",
        "GetFindings",
        "GetFlowLogsIntegrationTemplate",
        "GetIdentityVerificationAttributes",
        "GetInstances",
        "GetIntrospectionSchema",
        "GetLaunchTemplateData",
        "GetLaunchTemplateData",
        "GetLogRecord",
        "GetParameters",
        "GetPolicyVersion",
        "GetPublicAccessBlock",
        "GetQueryResults",
        "GetRegions",
        "GetSMSAttributes",
        "GetSMSSandboxAccountStatus",
        "GetSendQuota",
        "GetTransitGatewayRouteTableAssociations",
        "GetUserPolicy",
        "HeadObject",
        "ListAccessKeys",
        "ListAccounts",
        "ListAllMyBuckets",
        "ListAssociatedAccessPolicies",
        "ListAttachedUserPolicies",
        "ListClusters",
        "ListDetectors",
        "ListDomains",
        "ListFindings",
        "ListHostedZones",
        "ListIPSets",
        "ListIdentities",
        "ListInstanceProfiles",
        "ListObjects",
        "ListOrganizationalUnitsForParent",
        "ListOriginationNumbers",
        "ListPolicyVersions",
        "ListRoles",
        "ListRoles",
        "ListRules",
        "ListServiceQuotas",
        "ListSubscriptions",
        "ListTargetsByRule",
        "ListTopics",
        "ListUsers",
        "LookupEvents",
        "Search",
    ],
    "threat_detection_llm_jacking_threshold": 0.4,
    "threat_detection_llm_jacking_minutes": 1440,
    "threat_detection_llm_jacking_actions": [
        "PutUseCaseForModelAccess",
        "PutFoundationModelEntitlement",
        "PutModelInvocationLoggingConfiguration",
        "CreateFoundationModelAgreement",
        "InvokeModel",
        "InvokeModelWithResponseStream",
        "GetUseCaseForModelAccess",
        "GetModelInvocationLoggingConfiguration",
        "GetFoundationModelAvailability",
        "ListFoundationModelAgreementOffers",
        "ListFoundationModels",
        "ListProvisionedModelThroughputs",
    ],
    "check_rds_instance_replicas": False,
    "days_to_expire_threshold": 7,
    "insecure_key_algorithms": [
        "RSA-1024",
    ],
    "eks_required_log_types": [
        "api",
        "audit",
        "authenticator",
        "controllerManager",
        "scheduler",
    ],
    "eks_cluster_oldest_version_supported": "1.28",
    "excluded_sensitive_environment_variables": [],
    "elb_min_azs": 2,
    "elbv2_min_azs": 2,
    "secrets_ignore_patterns": [],
    "max_days_secret_unused": 90,
    "max_days_secret_unrotated": 90,
}

config_azure = {
    "shodan_api_key": None,
    "php_latest_version": "8.2",
    "python_latest_version": "3.12",
    "java_latest_version": "17",
}

config_gcp = {"shodan_api_key": None}

config_kubernetes = {
    "audit_log_maxbackup": 10,
    "audit_log_maxsize": 100,
    "audit_log_maxage": 30,
    "apiserver_strong_ciphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ],
    "kubelet_strong_ciphers": [
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
    ],
}


class Test_Config:
    @mock.patch(
        "prowler.config.config.requests.get", new=mock_prowler_get_latest_release
    )
    @mock.patch("prowler.config.config.prowler_version", new=MOCK_PROWLER_VERSION)
    def test_check_current_version_with_latest(self):
        assert (
            check_current_version()
            == f"Prowler {MOCK_PROWLER_VERSION} (You are running the latest version, yay!)"
        )

    @mock.patch(
        "prowler.config.config.requests.get", new=mock_prowler_get_latest_release
    )
    @mock.patch("prowler.config.config.prowler_version", new=MOCK_OLD_PROWLER_VERSION)
    def test_check_current_version_with_old(self):
        assert (
            check_current_version()
            == f"Prowler {MOCK_OLD_PROWLER_VERSION} (latest is {MOCK_PROWLER_VERSION}, upgrade for the latest features)"
        )

    @mock.patch(
        "prowler.config.config.requests.get", new=mock_prowler_get_latest_release
    )
    @mock.patch(
        "prowler.config.config.prowler_version", new=MOCK_PROWLER_MASTER_VERSION
    )
    def test_check_current_version_with_master_version(self):
        assert (
            check_current_version()
            == f"Prowler {MOCK_PROWLER_MASTER_VERSION} (You are running the latest version, yay!)"
        )

    def test_get_available_compliance_frameworks(self):
        compliance_frameworks = [
            "cisa_aws",
            "soc2_aws",
            "cis_1.4_aws",
            "cis_1.5_aws",
            "mitre_attack_aws",
            "gdpr_aws",
            "aws_foundational_security_best_practices_aws",
            "iso27001_2013_aws",
            "hipaa_aws",
            "cis_2.0_aws",
            "gxp_21_cfr_part_11_aws",
            "aws_well_architected_framework_security_pillar_aws",
            "gxp_eu_annex_11_aws",
            "nist_800_171_revision_2_aws",
            "nist_800_53_revision_4_aws",
            "nist_800_53_revision_5_aws",
            "ens_rd2022_aws",
            "nist_csf_1.1_aws",
            "aws_well_architected_framework_reliability_pillar_aws",
            "aws_audit_manager_control_tower_guardrails_aws",
            "rbi_cyber_security_framework_aws",
            "ffiec_aws",
            "pci_3.2.1_aws",
            "fedramp_moderate_revision_4_aws",
            "fedramp_low_revision_4_aws",
            "cis_2.0_gcp",
            "cis_1.8_kubernetes",
            "kisa_isms-p_2023_aws",
            "kisa_isms-p_2023-korean_aws",
        ]
        assert (
            get_available_compliance_frameworks().sort() == compliance_frameworks.sort()
        )

    def test_load_and_validate_config_file_aws(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config.yaml"
        provider = "aws"
        assert load_and_validate_config_file(provider, config_test_file) == config_aws

    def test_load_and_validate_config_file_gcp(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config.yaml"
        provider = "gcp"

        assert load_and_validate_config_file(provider, config_test_file) == config_gcp

    def test_load_and_validate_config_file_kubernetes(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config.yaml"
        provider = "kubernetes"
        assert (
            load_and_validate_config_file(provider, config_test_file)
            == config_kubernetes
        )

    def test_load_and_validate_config_file_azure(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config.yaml"
        provider = "azure"

        assert load_and_validate_config_file(provider, config_test_file) == config_azure

    def test_load_and_validate_config_file_old_format(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/config_old.yaml"
        assert load_and_validate_config_file("aws", config_test_file) == old_config_aws
        assert load_and_validate_config_file("gcp", config_test_file) == {}
        assert load_and_validate_config_file("azure", config_test_file) == {}
        assert load_and_validate_config_file("kubernetes", config_test_file) == {}

    def test_load_and_validate_config_file_invalid_config_file_path(self, caplog):
        provider = "aws"
        config_file_path = "invalid/path/to/fixer_config.yaml"

        with caplog.at_level(logging.ERROR):
            result = load_and_validate_config_file(provider, config_file_path)
            assert "FileNotFoundError" in caplog.text
            assert result == {}

    def test_load_and_validate_fixer_config_aws(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/fixer_config.yaml"
        provider = "aws"

        assert load_and_validate_fixer_config_file(provider, config_test_file)

    def test_load_and_validate_fixer_config_gcp(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/fixer_config.yaml"
        provider = "gcp"

        assert load_and_validate_fixer_config_file(provider, config_test_file) == {}

    def test_load_and_validate_fixer_config_kubernetes(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/fixer_config.yaml"
        provider = "kubernetes"

        assert load_and_validate_fixer_config_file(provider, config_test_file) == {}

    def test_load_and_validate_fixer_config_azure(self):
        path = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        config_test_file = f"{path}/fixtures/fixer_config.yaml"
        provider = "azure"

        assert load_and_validate_fixer_config_file(provider, config_test_file) == {}

    def test_load_and_validate_fixer_config_invalid_fixer_config_path(self, caplog):
        provider = "aws"
        fixer_config_path = "invalid/path/to/fixer_config.yaml"

        with caplog.at_level(logging.ERROR):
            result = load_and_validate_fixer_config_file(provider, fixer_config_path)
            assert "FileNotFoundError" in caplog.text
            assert result == {}
