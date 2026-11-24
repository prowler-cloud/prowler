"""Vault pagination and freshness through the production Backup collector."""

from collections import Counter
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from boto3 import Session
from botocore.exceptions import StubResponseError
from botocore.stub import Stubber
from freezegun import freeze_time

from prowler.providers.aws.services.backup.backup_service import Backup
from prowler.providers.aws.services.ec2.ec2_service import Volume

ACCOUNT = "111122223333"
EAST = "us-east-1"
WEST = "us-west-2"
CHECK = "ec2_ebs_volume_backup_recovery_point_recent"
NOW = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)


def volume(number, region=EAST):
    volume_id = f"vol-{number:017x}"
    return Volume(
        id=volume_id,
        arn=f"arn:aws:ec2:{region}:{ACCOUNT}:volume/{volume_id}",
        region=region,
        encrypted=True,
    )


def vault(region=EAST, **changes):
    return {
        "BackupVaultName": "test-vault",
        "BackupVaultArn": f"arn:aws:backup:{region}:{ACCOUNT}:backup-vault:test-vault",
        "VaultType": "BACKUP_VAULT",
        "EncryptionKeyArn": f"arn:aws:kms:{region}:{ACCOUNT}:key/fixture",
        "NumberOfRecoveryPoints": 3,
        "Locked": False,
    } | changes


def point(number, region=EAST, hours=1, **changes):
    return {
        "RecoveryPointArn": f"arn:aws:ec2:{region}::snapshot/snap-{number:017x}",
        "ResourceArn": volume(number, region).arn,
        "ResourceType": "EBS",
        "BackupVaultArn": vault(region)["BackupVaultArn"],
        "Status": "COMPLETED",
        "CreationDate": NOW - timedelta(hours=hours),
        "IsEncrypted": True,
    } | changes


def add_pages(stub, operation, result_key, pages, **params):
    for index, page in enumerate(pages):
        expected = params if not index else params | {"NextToken": str(index)}
        if isinstance(page, str):
            stub.add_client_error(
                operation, service_error_code=page, expected_params=expected
            )
        else:
            response = {result_key: list(page)}
            if index + 1 < len(pages):
                response["NextToken"] = str(index + 1)
            stub.add_response(operation, response, expected)


def queue_legacy_init(stub, region=EAST, *, vault_pages=None, tags=True):
    if vault_pages is None:
        vault_pages = ((vault(region),),)
    add_pages(stub, "list_backup_vaults", "BackupVaultList", vault_pages)
    if tags:
        stub.add_response(
            "list_tags", {"Tags": {}}, {"ResourceArn": vault(region)["BackupVaultArn"]}
        )
    stub.add_response("list_backup_plans", {"BackupPlansList": []}, {})
    stub.add_response("list_report_plans", {"ReportPlans": []}, {})


def queue_points(stub, pages, *, tag=None):
    add_pages(
        stub,
        "list_recovery_points_by_backup_vault",
        "RecoveryPoints",
        pages,
        BackupVaultName="test-vault",
    )
    if tag is not None:
        stub.add_response(
            "list_tags", {"Tags": {"fixture": "yes"}}, {"ResourceArn": tag}
        )


@pytest.fixture
def setup_backup(monkeypatch):
    import contextlib

    with contextlib.ExitStack() as stack:
        stubs = []
        unexpected = []

        def factory(
            *,
            regions=(EAST,),
            resources=(),
            enabled=True,
            checks=(CHECK,),
            limit=1,
        ):
            session = Session(
                aws_access_key_id="testing",
                aws_secret_access_key="testing",
                region_name=EAST,
            )
            clients = {}
            regional_stubs = {}
            calls = []
            for region in regions:
                client = session.client("backup", region_name=region)
                client.region = region
                clients[region] = client

                def record(
                    operation, params, *, original=client._make_api_call, region=region
                ):
                    calls.append((region, operation, params.copy()))
                    try:
                        return original(operation, params)
                    except StubResponseError as error:
                        unexpected.append(str(error))
                        raise

                monkeypatch.setattr(client, "_make_api_call", record)
                regional_stubs[region] = stack.enter_context(Stubber(client))
                stubs.append(regional_stubs[region])

            provider = SimpleNamespace(
                identity=SimpleNamespace(
                    account=ACCOUNT,
                    account_arn=f"arn:aws:iam::{ACCOUNT}:root",
                    partition="aws",
                ),
                audit_resources=list(resources),
                audit_config={
                    "aws_backup_ebs_recovery_evidence_enabled": enabled,
                    "max_backup_recovery_points": limit,
                },
                audit_metadata=SimpleNamespace(expected_checks=list(checks)),
                fixer_config={},
                session=SimpleNamespace(
                    current_session=SimpleNamespace(
                        client=lambda _service, region: clients[EAST]
                    )
                ),
                generate_regional_clients=lambda _service: clients,
                get_default_region=lambda _service, global_service: EAST,
            )

            def collect():
                with freeze_time(NOW):
                    backup = Backup(provider)
                stack.callback(backup.thread_pool.shutdown)
                return backup

            return SimpleNamespace(
                collect=collect, provider=provider, stubs=regional_stubs, calls=calls
            )

        yield factory
        assert not unexpected
        for stub in stubs:
            stub.assert_no_pending_responses()


def scope_results(backup, *volumes, hours=48):
    return backup.evaluate_ebs_recovery_points(volumes, hours)


def test_freshness_uses_both_vault_pages_before_the_legacy_limit(setup_backup):
    env = setup_backup()
    stub = env.stubs[EAST]
    first, second = point(1, hours=2), point(2)
    queue_legacy_init(stub)
    queue_points(stub, ((first,), (second,)), tag=second["RecoveryPointArn"])
    backup = env.collect()

    assert [row.arn for row in backup.recovery_points] == [second["RecoveryPointArn"]]
    assert backup.recovery_points[0].tags == [{"fixture": "yes"}]
    results = scope_results(backup, volume(1), volume(2))
    assert {
        arn: (decision.status, decision.point.arn) for arn, decision in results.items()
    } == {
        volume(1).arn: ("PASS", first["RecoveryPointArn"]),
        volume(2).arn: ("PASS", second["RecoveryPointArn"]),
    }
    assert Counter(op for _, op, _ in env.calls) == {
        "ListBackupVaults": 1,
        "ListBackupPlans": 1,
        "ListReportPlans": 1,
        "ListRecoveryPointsByBackupVault": 2,
        "ListTags": 2,
    }


def test_an_explicit_volume_recovers_a_filtered_vault_once(setup_backup):
    target = volume(1)
    env = setup_backup(resources=(target.arn,))
    stub = env.stubs[EAST]
    queue_legacy_init(stub, tags=False)
    queue_points(stub, ((point(1), point(2)),))
    backup = env.collect()

    assert backup.backup_vaults == backup.recovery_points == []
    for _ in range(2):
        result = scope_results(backup, target)
        assert set(result) == {target.arn}
        assert result[target.arn].status == "PASS"
    assert backup.recovery_points == []
    assert [op for _, op, _ in env.calls] == [
        "ListBackupVaults",
        "ListBackupPlans",
        "ListReportPlans",
        "ListRecoveryPointsByBackupVault",
    ]


@pytest.mark.parametrize(
    ("pages", "expected"),
    [
        (((),), "FAIL"),
        (("AccessDeniedException",), "SKIP"),
    ],
    ids=["read-empty", "first-page-denied"],
)
def test_empty_and_unreadable_yield_different_decisions(setup_backup, pages, expected):
    env = setup_backup()
    stub = env.stubs[EAST]
    queue_legacy_init(stub)
    queue_points(stub, pages)
    backup = env.collect()

    assert backup.recovery_points == []
    assert scope_results(backup, volume(1))[volume(1).arn].status == expected


def test_a_positive_page_cannot_hide_a_later_access_denial(setup_backup, caplog):
    row = point(1)
    env = setup_backup()
    stub = env.stubs[EAST]
    queue_legacy_init(stub)
    queue_points(stub, ((row,), "AccessDeniedException"), tag=row["RecoveryPointArn"])
    backup = env.collect()

    assert [record.arn for record in backup.recovery_points] == [
        row["RecoveryPointArn"]
    ]
    assert scope_results(backup, volume(1))[volume(1).arn].status == "SKIP"
    assert any(
        "backup:ListRecoveryPointsByBackupVault" in message
        and "AccessDeniedException" in message
        and EAST in message
        and "test-vault" in message
        for message in caplog.messages
    )


def test_conflicting_vault_identity_cannot_pass_a_local_volume(setup_backup):
    row = point(1, BackupVaultArn=vault(WEST)["BackupVaultArn"])
    env = setup_backup()
    stub = env.stubs[EAST]
    queue_legacy_init(stub)
    queue_points(stub, ((row,),), tag=row["RecoveryPointArn"])
    backup = env.collect()

    assert backup.recovery_points[0].arn == row["RecoveryPointArn"]
    assert scope_results(backup, volume(1))[volume(1).arn].status == "SKIP"


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"CreationDate": NOW - timedelta(hours=48)}, "PASS"),
        ({"CreationDate": NOW}, "PASS"),
        ({"CreationDate": NOW - timedelta(hours=48, microseconds=1)}, "FAIL"),
        ({"CreationDate": NOW + timedelta(microseconds=1)}, "SKIP"),
        ({"CreationDate": NOW.replace(tzinfo=None)}, "SKIP"),
        ({"CreationDate": None}, "SKIP"),
        ({"Status": "AVAILABLE"}, "PASS"),
        ({"Status": "CREATING"}, "FAIL"),
        ({"Status": "UNKNOWN"}, "SKIP"),
        ({"Status": None}, "SKIP"),
        ({"RecoveryPointArn": None}, "SKIP"),
        ({"RecoveryPointArn": "arn:aws:ec2:us-east-1::snapshot/snap-1234"}, "SKIP"),
        ({"RecoveryPointArn": "arn:aws:ec2:us-east-1::snapshot/snap-1234abcd"}, "PASS"),
        (
            {
                "RecoveryPointArn": "arn:aws:ec2:us-east-1:222233334444:snapshot/snap-00000000000000001"
            },
            "SKIP",
        ),
        (
            {
                "RecoveryPointArn": "arn:aws-cn:ec2:us-east-1::snapshot/snap-00000000000000001"
            },
            "SKIP",
        ),
        ({"BackupVaultArn": None}, "SKIP"),
        ({"VaultType": "LOGICALLY_AIR_GAPPED_BACKUP_VAULT"}, "SKIP"),
        ({"ResourceType": "EC2"}, "SKIP"),
        ({"ResourceArn": None}, "SKIP"),
        ({"ResourceArn": volume(2).arn}, "FAIL"),
        ({"ResourceArn": volume(1, WEST).arn}, "FAIL"),
        ({"ResourceArn": volume(1).arn.replace(ACCOUNT, "222233334444")}, "FAIL"),
        ({"ResourceArn": volume(1).arn.replace("arn:aws:", "arn:aws-cn:")}, "FAIL"),
        ({"SourceBackupVaultArn": vault()["BackupVaultArn"]}, "SKIP"),
        ({"SourceBackupVaultArn": vault(WEST)["BackupVaultArn"]}, "SKIP"),
        ({"SourceBackupVaultArn": "unknown"}, "SKIP"),
        (
            {
                "SourceBackupVaultArn": vault(WEST)["BackupVaultArn"],
                "ResourceArn": None,
            },
            "FAIL",
        ),
        (
            {"SourceBackupVaultArn": vault()["BackupVaultArn"], "ResourceArn": None},
            "SKIP",
        ),
        (
            {
                "SourceBackupVaultArn": vault(WEST)["BackupVaultArn"],
                "ResourceArn": volume(1, WEST).arn,
            },
            "FAIL",
        ),
    ],
    ids=[
        "48h-inclusive",
        "observation-time-inclusive",
        "older-than-48h",
        "future",
        "timezone-missing",
        "time-missing",
        "available",
        "creating",
        "status-unknown",
        "status-missing",
        "point-arn-missing",
        "point-id-malformed",
        "legacy-snapshot-id",
        "point-account-conflict",
        "point-partition-conflict",
        "vault-arn-missing",
        "vault-type-conflict",
        "resource-type-conflict",
        "origin-missing",
        "other-volume",
        "other-region",
        "other-account",
        "other-partition",
        "copy-local",
        "copy-contradicted",
        "copy-scope-unknown",
        "copy-route-outside",
        "copy-origin-missing",
        "copy-outside",
    ],
)
def test_point_identity_status_and_time(setup_backup, changes, expected):
    target = volume(1)
    env = setup_backup(resources=(target.arn,))
    stub = env.stubs[EAST]
    row = {
        key: value for key, value in point(1, **changes).items() if value is not None
    }
    queue_legacy_init(stub, tags=False)
    queue_points(stub, ((row,),))

    assert scope_results(env.collect(), target)[target.arn].status == expected


@pytest.mark.parametrize(
    ("vault_pages", "expected"),
    [
        (((),), "FAIL"),
        (((vault(VaultType="LOGICALLY_AIR_GAPPED_BACKUP_VAULT"),),), "FAIL"),
        (((vault(VaultType="RESTORE_ACCESS_BACKUP_VAULT"),),), "FAIL"),
        (
            (
                (
                    vault(
                        BackupVaultArn=vault()["BackupVaultArn"].replace(
                            ACCOUNT, "222233334444"
                        )
                    ),
                ),
            ),
            "FAIL",
        ),
        (((vault(VaultType=""),),), "SKIP"),
        (((vault(BackupVaultArn="invalid"),),), "SKIP"),
        (((vault(BackupVaultName="unknown"),),), "SKIP"),
        (((vault(),), (vault(VaultType="RESTORE_ACCESS_BACKUP_VAULT"),)), "SKIP"),
        (("AccessDeniedException",), "SKIP"),
        (((vault(),), "AccessDeniedException"), "SKIP"),
    ],
    ids=[
        "empty",
        "air-gapped",
        "restore-access",
        "foreign-owner",
        "type-unknown",
        "owner-unknown",
        "name-conflict",
        "type-conflict",
        "denied",
        "partially-denied",
    ],
)
def test_vault_discovery_scope(setup_backup, vault_pages, expected):
    target = volume(1)
    env = setup_backup(resources=(target.arn,))
    queue_legacy_init(env.stubs[EAST], tags=False, vault_pages=vault_pages)

    assert scope_results(env.collect(), target)[target.arn].status == expected
    assert all(
        operation != "ListRecoveryPointsByBackupVault" for _, operation, _ in env.calls
    )


@pytest.mark.parametrize("missing_lock_from", ["standard", "special"])
def test_missing_optional_vault_lock_keeps_freshness_evidence(
    setup_backup, missing_lock_from
):
    standard = vault()
    special = vault(
        BackupVaultName="special-vault",
        BackupVaultArn=f"arn:aws:backup:{EAST}:{ACCOUNT}:backup-vault:special-vault",
        VaultType="LOGICALLY_AIR_GAPPED_BACKUP_VAULT",
    )
    projects_standard = missing_lock_from == "special"
    (special if projects_standard else standard).pop("Locked")
    env = setup_backup()
    stub = env.stubs[EAST]
    queue_legacy_init(stub, vault_pages=((standard, special),), tags=projects_standard)
    observed = point(1)
    queue_points(
        stub,
        ((observed,),),
        tag=observed["RecoveryPointArn"] if projects_standard else None,
    )

    backup = env.collect()
    for _ in range(2):
        assert scope_results(backup, volume(1))[volume(1).arn].status == "PASS"
    assert [record.arn for record in backup.backup_vaults] == (
        [standard["BackupVaultArn"]] if projects_standard else []
    )
    calls = Counter(op for _, op, _ in env.calls)
    assert calls["ListBackupVaults"] == calls["ListRecoveryPointsByBackupVault"] == 1
    assert calls["ListTags"] == (2 if projects_standard else 0)


@pytest.mark.parametrize("later_page_denied", [False, True], ids=["complete", "denied"])
def test_vault_discovery_reads_later_pages_after_legacy_model_error(
    setup_backup, later_page_denied
):
    special = vault(
        BackupVaultName="special-vault",
        BackupVaultArn=f"arn:aws:backup:{EAST}:{ACCOUNT}:backup-vault:special-vault",
        VaultType="RESTORE_ACCESS_BACKUP_VAULT",
    )
    special.pop("Locked")
    env = setup_backup()
    stub = env.stubs[EAST]
    later_page = "AccessDeniedException" if later_page_denied else (vault(),)
    queue_legacy_init(stub, vault_pages=((special,), later_page), tags=False)
    if not later_page_denied:
        queue_points(stub, ((point(1),),))

    backup = env.collect()
    assert backup.backup_vaults == []
    expected = "SKIP" if later_page_denied else "PASS"
    assert scope_results(backup, volume(1))[volume(1).arn].status == expected
    calls = Counter(op for _, op, _ in env.calls)
    assert calls["ListBackupVaults"] == 2
    assert calls["ListRecoveryPointsByBackupVault"] == (0 if later_page_denied else 1)
    assert calls["ListTags"] == 0


def test_duplicate_point_conflict_affects_only_its_volumes(setup_backup):
    first, second, third = volume(1), volume(2), volume(3)
    repeated = point(1)
    conflict = point(2, RecoveryPointArn=repeated["RecoveryPointArn"])
    env = setup_backup(resources=(first.arn, second.arn, third.arn))
    stub = env.stubs[EAST]
    queue_legacy_init(stub, tags=False)
    queue_points(stub, ((repeated, point(3)), (repeated, conflict)))

    results = scope_results(env.collect(), first, second, third)
    assert [results[volume.arn].status for volume in (first, second, third)] == [
        "SKIP",
        "SKIP",
        "PASS",
    ]


def test_unreadable_region_does_not_hide_another_regions_evidence(setup_backup):
    east, west = volume(1), volume(1, WEST)
    env = setup_backup(resources=(east.arn, west.arn), regions=(EAST, WEST))
    queue_legacy_init(env.stubs[EAST], tags=False)
    queue_legacy_init(env.stubs[WEST], WEST, tags=False)
    queue_points(env.stubs[EAST], ("AccessDeniedException",))
    queue_points(env.stubs[WEST], ((point(1, WEST),),))

    results = scope_results(env.collect(), east, west)
    assert results[east.arn].status == "SKIP"
    assert results[west.arn].status == "PASS"


def test_repeated_token_is_unreadable_and_keeps_observed_points(setup_backup):
    target = volume(1)
    env = setup_backup(resources=(target.arn,))
    stub = env.stubs[EAST]
    queue_legacy_init(stub, tags=False)
    for index in range(2):
        stub.add_response(
            "list_recovery_points_by_backup_vault",
            {"RecoveryPoints": [point(index + 1)], "NextToken": "repeat"},
            {"BackupVaultName": "test-vault"}
            | ({"NextToken": "repeat"} if index else {}),
        )
    backup = env.collect()

    assert scope_results(backup, target)[target.arn].status == "SKIP"
    (reads,) = backup._ebs_evidence.points.values()
    (read,) = reads
    assert len(read.rows) == 2
    assert read.pages_seen == 2
    assert read.error_code == "PaginationError"


@pytest.mark.parametrize(
    "tokens",
    [(42,), ("next", "next"), ("next", "later", "next")],
    ids=["numeric", "repeat", "cycle"],
)
def test_bad_recovery_point_tokens_keep_legacy_results(setup_backup, tokens):
    target = volume(1)
    for enabled in (True, False):
        env = setup_backup(enabled=enabled)
        stub = env.stubs[EAST]
        queue_legacy_init(stub)
        newest = point(1, IsEncrypted=False)
        for index, token in enumerate(tokens):
            params = {"BackupVaultName": "test-vault"}
            if index:
                params["NextToken"] = tokens[index - 1]
            row = newest if index == len(tokens) - 1 else point(index + 2, hours=2)
            stub.add_response(
                "list_recovery_points_by_backup_vault",
                {"RecoveryPoints": [row], "NextToken": str(token)},
                params,
            )
        if isinstance(tokens[-1], int):

            def numeric_token(parsed, **_):
                parsed["NextToken"] = tokens[-1]

            stub.client.meta.events.register(
                "after-call.backup.ListRecoveryPointsByBackupVault", numeric_token
            )
        stub.add_response(
            "list_tags", {"Tags": {}}, {"ResourceArn": newest["RecoveryPointArn"]}
        )

        backup = env.collect()
        assert [(row.arn, row.encrypted) for row in backup.recovery_points] == [
            (newest["RecoveryPointArn"], False)
        ]
        calls = Counter(op for _, op, _ in env.calls)
        assert calls["ListRecoveryPointsByBackupVault"] == len(tokens)
        assert calls["ListTags"] == 2
        if enabled:
            assert scope_results(backup, target)[target.arn].status == "SKIP"
            (reads,) = backup._ebs_evidence.points.values()
            (read,) = reads
            assert (read.pages_seen, len(read.rows), read.error_code) == (
                len(tokens),
                len(tokens),
                "PaginationError",
            )
        else:
            assert scope_results(backup, target) == {}


def test_a_missing_recovery_points_array_is_unreadable(setup_backup):
    target = volume(1)
    env = setup_backup(resources=(target.arn,))
    stub = env.stubs[EAST]
    queue_legacy_init(stub, tags=False)
    stub.add_response(
        "list_recovery_points_by_backup_vault", {}, {"BackupVaultName": "test-vault"}
    )

    assert scope_results(env.collect(), target)[target.arn].status == "SKIP"


@pytest.mark.parametrize(
    ("enabled", "checks"),
    [(False, (CHECK,)), (True, ("backup_recovery_point_encrypted",))],
    ids=["disabled", "check-unselected"],
)
def test_freshness_collection_is_opt_in_and_only_for_selected_check(
    setup_backup, enabled, checks
):
    target = volume(1)
    env = setup_backup(resources=(target.arn,), enabled=enabled, checks=checks)
    queue_legacy_init(env.stubs[EAST], tags=False)

    backup = env.collect()
    assert backup._ebs_evidence is None
    assert scope_results(backup, target) == {}
    assert all(
        operation != "ListRecoveryPointsByBackupVault" for _, operation, _ in env.calls
    )


def test_a_new_audit_reloads_its_own_evidence(setup_backup):
    target = volume(1)
    env = setup_backup(resources=(target.arn,))
    stub = env.stubs[EAST]
    queue_legacy_init(stub, tags=False)
    queue_points(stub, ((point(1),),))
    backup = env.collect()
    assert scope_results(backup, target)[target.arn].status == "PASS"

    env.provider.audit_metadata = SimpleNamespace(expected_checks=[CHECK])
    add_pages(stub, "list_backup_vaults", "BackupVaultList", ((),))
    with freeze_time(NOW + timedelta(days=1)):
        assert scope_results(backup, target)[target.arn].status == "FAIL"
    assert Counter(operation for _, operation, _ in env.calls)["ListBackupVaults"] == 2
