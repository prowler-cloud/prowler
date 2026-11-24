"""Run the freshness check through the AWS SDK scan and CLI."""

import csv
import sys
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from importlib import import_module
from types import SimpleNamespace

import boto3
import pytest
from botocore.exceptions import StubResponseError
from botocore.stub import Stubber
from moto import mock_aws

from prowler.lib.scan.scan import Scan
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.service.service import AWSService
from prowler.providers.aws.services.backup.backup_service import Backup
from prowler.providers.common.provider import Provider

FRESHNESS = "ec2_ebs_volume_backup_recovery_point_recent"
ENCRYPTION = "backup_recovery_point_encrypted"
REPORT_PLANS = "backup_reportplans_exist"
REGION = "us-east-1"
NOW = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)
ENABLED = "aws_backup_ebs_recovery_evidence_enabled"
HOURS = "aws_backup_ebs_recovery_point_max_age_hours"
AWS_SERVICES = "prowler.providers.aws.services"
CLIENT_MODULES = (
    f"{AWS_SERVICES}.ec2.ec2_client",
    f"{AWS_SERVICES}.backup.backup_client",
)


@pytest.fixture
def aws_inventory(monkeypatch):
    # These modules own a service client for the process's active provider.
    for module_name in (
        *CLIENT_MODULES,
        f"{AWS_SERVICES}.backup.{ENCRYPTION}.{ENCRYPTION}",
        f"{AWS_SERVICES}.backup.{REPORT_PLANS}.{REPORT_PLANS}",
    ):
        package_name, name = module_name.rsplit(".", 1)
        package = import_module(package_name)
        monkeypatch.setattr(package, name, None, raising=False)
        monkeypatch.delattr(package, name)
        monkeypatch.setitem(sys.modules, module_name, None)
        monkeypatch.delitem(sys.modules, module_name)
    monkeypatch.setattr(Provider, "_global", None)
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)

    collect = AWSService.__threading_call__

    def collect_volume_inventory(self, call, iterator=None):
        if self.service != "ec2" or call.__name__ == "_describe_volumes":
            collect(self, call, iterator)

    monkeypatch.setattr(AWSService, "__threading_call__", collect_volume_inventory)

    start_evidence = Backup._start_ebs_evidence

    def start_evidence_at_fixture_time(self):
        evidence = start_evidence(self)
        evidence.observed_at = NOW
        return evidence

    monkeypatch.setattr(Backup, "_start_ebs_evidence", start_evidence_at_fixture_time)

    with mock_aws(), ExitStack() as stack:
        ec2 = boto3.client("ec2", region_name=REGION)
        account = boto3.client("sts", region_name=REGION).get_caller_identity()[
            "Account"
        ]
        ids = []
        for index in range(3):
            response = ec2.create_volume(
                AvailabilityZone=f"{REGION}a",
                Size=1,
                Encrypted=True,
                TagSpecifications=[
                    {
                        "ResourceType": "volume",
                        "Tags": [
                            {"Key": "Audit", "Value": "yes" if index == 0 else "no"}
                        ],
                    }
                ],
            )
            ids.append(response["VolumeId"])
        arns = [
            f"arn:aws:ec2:{REGION}:{account}:volume/{volume_id}" for volume_id in ids
        ]
        vault_arn = f"arn:aws:backup:{REGION}:{account}:backup-vault:fixture-vault"
        points = [
            {
                "RecoveryPointArn": f"arn:aws:ec2:{REGION}::snapshot/snap-{index:017x}",
                "BackupVaultArn": vault_arn,
                "ResourceArn": arn,
                "ResourceType": "EBS",
                "Status": "COMPLETED",
                "CreationDate": NOW - timedelta(hours=age),
                "IsEncrypted": True,
            }
            for index, (arn, age) in enumerate(zip(arns, (2, 1)), start=1)
        ]
        calls = []
        unexpected = []
        stubs = []
        inventory = SimpleNamespace(
            ids=ids,
            arns=arns,
            points=points,
            calls=calls,
            tag_value="yes",
            deny_second_page=False,
            invalid_second_token=False,
        )
        generate = AwsProvider.generate_regional_clients

        def generate_clients(self, service):
            clients = generate(self, service)
            if service not in ("backup", "resourcegroupstaggingapi"):
                return clients
            assert set(clients) == {REGION}
            client = clients[REGION]
            stub = stack.enter_context(Stubber(client))
            stubs.append(stub)
            if service == "resourcegroupstaggingapi":
                matches = []
                if inventory.tag_value == "yes":
                    matches.append(
                        {
                            "ResourceARN": arns[0],
                            "Tags": [{"Key": "Audit", "Value": "yes"}],
                        }
                    )
                stub.add_response(
                    "get_resources",
                    {"ResourceTagMappingList": matches, "PaginationToken": ""},
                    {"TagFilters": [{"Key": "Audit", "Values": [inventory.tag_value]}]},
                )
                return clients

            make_api_call = client._make_api_call

            def record(operation, params):
                calls.append((operation, params.copy()))
                try:
                    result = make_api_call(operation, params)
                    if (
                        inventory.invalid_second_token
                        and operation == "ListRecoveryPointsByBackupVault"
                        and params.get("NextToken") == "page-2"
                    ):
                        result["NextToken"] = 42
                    return result
                except StubResponseError as error:
                    unexpected.append(error)
                    raise

            monkeypatch.setattr(client, "_make_api_call", record)
            stub.add_response(
                "list_backup_vaults",
                {
                    "BackupVaultList": [
                        {
                            "BackupVaultName": "fixture-vault",
                            "BackupVaultArn": vault_arn,
                            "VaultType": "BACKUP_VAULT",
                            "EncryptionKeyArn": f"arn:aws:kms:{REGION}:{account}:key/fixture",
                            "NumberOfRecoveryPoints": len(points),
                            "Locked": False,
                        }
                    ]
                },
                {},
            )
            if not self.audit_resources:
                stub.add_response("list_tags", {"Tags": {}}, {"ResourceArn": vault_arn})
            stub.add_response("list_backup_plans", {"BackupPlansList": []}, {})
            stub.add_response("list_report_plans", {"ReportPlans": []}, {})
            stub.add_response(
                "list_recovery_points_by_backup_vault",
                {"RecoveryPoints": points[:1], "NextToken": "page-2"},
                {"BackupVaultName": "fixture-vault"},
            )
            next_page = {"BackupVaultName": "fixture-vault", "NextToken": "page-2"}
            if inventory.deny_second_page:
                stub.add_client_error(
                    "list_recovery_points_by_backup_vault",
                    service_error_code="AccessDeniedException",
                    expected_params=next_page,
                )
            else:
                stub.add_response(
                    "list_recovery_points_by_backup_vault",
                    {"RecoveryPoints": points[1:]},
                    next_page,
                )
            if not self.audit_resources:
                selected = points[0] if inventory.deny_second_page else points[1]
                stub.add_response(
                    "list_tags",
                    {"Tags": {"Latest": "yes"}},
                    {"ResourceArn": selected["RecoveryPointArn"]},
                )
            return clients

        monkeypatch.setattr(AwsProvider, "generate_regional_clients", generate_clients)
        try:
            yield inventory
        finally:
            for name in CLIENT_MODULES:
                if name in sys.modules:
                    client = getattr(sys.modules[name], name.rsplit(".", 1)[1])
                    client.thread_pool.shutdown()
            assert not unexpected
            for stub in stubs:
                stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    ("other_check", "first_check"),
    [(ENCRYPTION, ENCRYPTION), (REPORT_PLANS, FRESHNESS)],
    ids=["backup-first", "freshness-first"],
)
def test_single_provider_sdk(aws_inventory, other_check, first_check):
    provider = AwsProvider(
        regions={REGION},
        config_content={ENABLED: True, "max_backup_recovery_points": 1},
    )
    scan = Scan(provider, checks=[FRESHNESS, other_check])
    assert scan.checks_to_execute[0] == first_check
    findings = [finding for _, batch in scan.scan() for finding in batch]
    freshness = {
        finding.resource_uid: finding
        for finding in findings
        if finding.metadata.CheckID == FRESHNESS
    }
    assert set(freshness) == set(aws_inventory.arns)
    for index, arn in enumerate(aws_inventory.arns):
        finding = freshness[arn]
        assert finding.region == REGION
        assert finding.resource_name == aws_inventory.ids[index]
        assert finding.account_uid == provider.identity.account
        assert "standard AWS Backup vault" in finding.status_extended
        assert "48 hours" in finding.status_extended
        if index < 2:
            assert finding.status.value == "PASS"
            assert (
                finding.raw["recovery_point_arn"]
                == aws_inventory.points[index]["RecoveryPointArn"]
            )
            assert finding.raw["status"] == "COMPLETED"
        else:
            assert finding.status.value == "FAIL"
            assert finding.status_extended == (
                f"No qualifying recovery point for EBS volume {aws_inventory.ids[index]} "
                "was observed in the scanned account's standard AWS Backup vaults in this "
                "Region within the previous 48 hours."
            )
    if other_check == ENCRYPTION:
        (finding,) = [
            finding for finding in findings if finding.metadata.CheckID == ENCRYPTION
        ]
        assert finding.status.value == "PASS"
        assert finding.resource_uid == aws_inventory.points[1]["RecoveryPointArn"]
    assert Counter(operation for operation, _ in aws_inventory.calls) == {
        "ListBackupVaults": 1,
        "ListBackupPlans": 1,
        "ListReportPlans": 1,
        "ListRecoveryPointsByBackupVault": 2,
        "ListTags": 2,
    }


@pytest.mark.parametrize("scope", ["arn", "tag"])
def test_cli_audits_selected_volume_with_vault_evidence(
    aws_inventory, monkeypatch, tmp_path, scope
):
    from prowler.__main__ import prowler

    config = tmp_path / "config.yaml"
    config.write_text(f"aws:\n  {ENABLED}: true\n  {HOURS}: 3\n")
    selector = (
        ["--resource-arn", aws_inventory.arns[0]]
        if scope == "arn"
        else ["--resource-tag", "Audit=yes"]
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prowler",
            "aws",
            "-b",
            "-z",
            "-f",
            REGION,
            "-c",
            FRESHNESS,
            "-M",
            "csv",
            "-o",
            str(tmp_path),
            "-F",
            "freshness",
            "--config-file",
            str(config),
            *selector,
        ],
    )
    prowler()
    with (tmp_path / "freshness.csv").open(newline="") as output:
        (row,) = list(csv.DictReader(output, delimiter=";"))
    assert row["CHECK_ID"] == FRESHNESS
    assert row["RESOURCE_UID"] == aws_inventory.arns[0]
    assert row["REGION"] == REGION
    assert row["STATUS"] == "PASS"
    assert "within the previous 3 hours" in row["STATUS_EXTENDED"]
    assert "standard AWS Backup vault" in row["STATUS_EXTENDED"]
    assert Counter(operation for operation, _ in aws_inventory.calls) == {
        "ListBackupVaults": 1,
        "ListBackupPlans": 1,
        "ListReportPlans": 1,
        "ListRecoveryPointsByBackupVault": 2,
    }


def test_disabled_by_default_skips_backup_and_ec2(aws_inventory):
    provider = AwsProvider(regions={REGION})
    assert provider.audit_config[ENABLED] is False
    scan = Scan(provider, checks=[FRESHNESS])
    assert [finding for _, batch in scan.scan() for finding in batch] == []
    assert all(module_name not in sys.modules for module_name in CLIENT_MODULES)
    assert aws_inventory.calls == []


def test_sdk_tag_filter_with_no_matching_volumes(aws_inventory):
    aws_inventory.tag_value = "missing"
    provider = AwsProvider(
        regions={REGION},
        resource_tags=["Audit=missing"],
        config_content={ENABLED: True, "max_backup_recovery_points": 1},
    )
    scan = Scan(provider, checks=[FRESHNESS])
    assert [finding for _, batch in scan.scan() for finding in batch] == []
    assert all(module_name not in sys.modules for module_name in CLIENT_MODULES)
    assert aws_inventory.calls == []


def test_sdk_omits_findings_when_a_later_page_is_denied(aws_inventory, caplog):
    aws_inventory.deny_second_page = True
    provider = AwsProvider(
        regions={REGION},
        config_content={ENABLED: True, "max_backup_recovery_points": 1},
    )
    scan = Scan(provider, checks=[FRESHNESS, ENCRYPTION])
    (finding,) = [finding for _, batch in scan.scan() for finding in batch]
    assert finding.metadata.CheckID == ENCRYPTION
    assert finding.resource_uid == aws_inventory.points[0]["RecoveryPointArn"]
    assert any(
        "backup:ListRecoveryPointsByBackupVault" in message
        and "AccessDeniedException" in message
        and "fixture-vault" in message
        for message in caplog.messages
    )


def test_sdk_keeps_encryption_finding_on_a_malformed_page_token(aws_inventory):
    aws_inventory.invalid_second_token = True
    aws_inventory.points[1]["IsEncrypted"] = False
    provider = AwsProvider(
        regions={REGION},
        config_content={ENABLED: True, "max_backup_recovery_points": 1},
    )
    scan = Scan(provider, checks=[FRESHNESS, ENCRYPTION])
    (finding,) = [finding for _, batch in scan.scan() for finding in batch]
    assert finding.metadata.CheckID == ENCRYPTION
    assert finding.resource_uid == aws_inventory.points[1]["RecoveryPointArn"]
    assert finding.status.value == "FAIL"
    assert [
        params.get("NextToken")
        for operation, params in aws_inventory.calls
        if operation == "ListRecoveryPointsByBackupVault"
    ] == [None, "page-2"]
