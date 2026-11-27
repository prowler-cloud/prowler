"""EBS recovery point evidence from standard AWS Backup vaults."""

import re
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Generic, Literal, TypeVar

from botocore.exceptions import ClientError

from prowler.lib.logger import logger

FRESHNESS_CHECK = "ec2_ebs_volume_backup_recovery_point_recent"
VAULT_ACTION = "backup:ListBackupVaults"
POINT_ACTION = "backup:ListRecoveryPointsByBackupVault"

_STANDARD_VAULT = "BACKUP_VAULT"
_OTHER_VAULT_TYPES = {
    "LOGICALLY_AIR_GAPPED_BACKUP_VAULT",
    "RESTORE_ACCESS_BACKUP_VAULT",
}
_ELIGIBLE_STATUS = {"COMPLETED", "AVAILABLE"}
_INELIGIBLE_STATUS = {"CREATING", "PARTIAL", "DELETING", "EXPIRED", "STOPPED"}
_ARN = re.compile(
    r"arn:(aws(?:-[a-z0-9]+)*):([a-z0-9-]+):([a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+):([0-9]{12}|):(.+)"
)
_EC2_ID = r"(?:[0-9a-f]{8}|[0-9a-f]{17})"
_VOLUME = re.compile(rf"volume/vol-{_EC2_ID}")
_SNAPSHOT = re.compile(rf"snapshot/snap-{_EC2_ID}")
_VAULT = re.compile(r"backup-vault:([A-Za-z0-9_-]{2,50})")
_BACKUP_POINT = re.compile(r"recovery-point:[A-Za-z0-9_-]+")

Scope = tuple[str, str, str]
T = TypeVar("T")


def _arn_parts(arn: str | None) -> tuple[Scope, str, str] | None:
    """Parse the scope, service and resource of a regional AWS ARN.

    Args:
        arn: The ARN to parse.

    Returns:
        A (scope, service, resource) tuple, or None for an invalid ARN.
        Scope is (partition, account, region). The account may be empty.
    """
    match = _ARN.fullmatch(arn) if isinstance(arn, str) else None
    if match is None:
        return None
    partition, service, region, account, resource = match.groups()
    return (partition, account, region), service, resource


def volume_scope(arn: str | None) -> Scope | None:
    """Return the partition, account and Region of an EC2 volume ARN."""
    parts = _arn_parts(arn)
    if parts is not None:
        scope, service, resource = parts
        if scope[1] and service == "ec2" and _VOLUME.fullmatch(resource):
            return scope
    return None


def _vault_identity(arn: str | None) -> tuple[Scope, str] | None:
    """Extract the scope and name of an account-bearing Backup vault ARN.

    Args:
        arn: The vault ARN to parse.

    Returns:
        A (scope, name) pair, or None if the ARN does not identify a
        Backup vault with an account.
    """
    parts = _arn_parts(arn)
    if parts is not None:
        scope, service, resource = parts
        name = _VAULT.fullmatch(resource)
        if service == "backup" and scope[1] and name is not None:
            return scope, name.group(1)
    return None


def _valid_point_arn(arn: str | None, scope: Scope) -> bool:
    """Check whether a recovery point ARN is compatible with the audit scope.

    Args:
        arn: The Backup recovery point or EC2 snapshot ARN to validate.
        scope: The audited partition, account and Region.

    Returns:
        True for a matching ARN. EC2 snapshot ARNs in the audited partition
        and Region may have an empty account field.
    """
    parts = _arn_parts(arn)
    if parts is None:
        return False
    point_scope, service, resource = parts
    if service == "ec2" and _SNAPSHOT.fullmatch(resource):
        partition, _, region = scope
        return point_scope in (scope, (partition, "", region))
    return (
        service == "backup"
        and point_scope == scope
        and _BACKUP_POINT.fullmatch(resource) is not None
    )


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _utc(value: object) -> datetime | None:
    if isinstance(value, datetime) and value.utcoffset() is not None:
        return value.astimezone(timezone.utc)
    return None


@dataclass
class CollectionResult(Generic[T]):
    """Keep observed rows and completion separately for one list operation."""

    rows: set[T] = field(default_factory=set)
    pages_seen: int = 0
    complete: bool = False
    error_code: str | None = None
    _has_next_page: bool = False

    def page_rows(self, page: Mapping, key: str) -> list[Mapping]:
        """Validate the result array and record pagination progress."""
        self.pages_seen += 1
        self._has_next_page = bool(page.get("NextToken"))

        rows = page.get(key)
        if not isinstance(rows, list) or not all(
            isinstance(row, Mapping) for row in rows
        ):
            self.error_code = "InvalidResult"
            return []
        return rows

    @contextmanager
    def read(
        self, action: str, scope: Scope, vault_arn: str | None = None
    ) -> Iterator[None]:
        """Record whether the caller consumed a complete list with a final page."""
        try:
            yield
        except Exception as error:
            self.error_code = type(error).__name__
            if isinstance(error, ClientError):
                self.error_code = error.response.get("Error", {}).get(
                    "Code", self.error_code
                )
            raise
        else:
            if not self.pages_seen or self._has_next_page:
                self.error_code = self.error_code or "MissingTerminalPage"
            self.complete = self.error_code is None
        finally:
            if not self.complete:
                log_unavailable(
                    action, scope, self.error_code, vault_arn, self.pages_seen
                )


def log_unavailable(
    action: str,
    scope: Scope,
    reason: str | None,
    vault_arn: str | None = None,
    pages: int | None = None,
    *,
    volume_arn: str | None = None,
) -> None:
    """Log a Backup availability failure with its IAM action and scope."""
    partition, account, region = scope
    logger.warning(
        "AWS Backup %s unavailable: partition=%s account=%s region=%s "
        "vault=%s volume=%s pages=%s reason=%s",
        action,
        partition,
        account,
        region,
        vault_arn,
        volume_arn,
        pages,
        reason,
    )


@dataclass(frozen=True)
class Vault:
    """Identity of a vault in the regional Backup catalog."""

    arn: str
    name: str
    region: str


@dataclass(frozen=True)
class VaultDescription:
    """The fields that determine whether a discovered vault is in scope."""

    arn: str | None
    name: str | None
    vault_type: str | None

    @classmethod
    def from_row(cls, row: Mapping) -> "VaultDescription":
        """Read the ownership, name and type fields from an AWS Backup row."""
        return cls(
            _text(row.get("BackupVaultArn")),
            _text(row.get("BackupVaultName")),
            _text(row.get("VaultType")),
        )


@dataclass(frozen=True)
class EbsRecoveryPoint:
    """Recovery point fields used to establish source, scope and freshness."""

    arn: str | None
    source_arn: str | None
    resource_type: str | None
    status: str | None
    creation_date: datetime | None
    vault_arn: str | None
    vault_type: str
    source_vault_arn: str | None

    @classmethod
    def from_row(cls, row: Mapping) -> "EbsRecoveryPoint":
        """Normalize a point from a vault whose standard type was confirmed."""
        source_vault_arn = row.get("SourceBackupVaultArn")
        return cls(
            arn=_text(row.get("RecoveryPointArn")),
            source_arn=_text(row.get("ResourceArn")),
            resource_type=_text(row.get("ResourceType")),
            status=_text(row.get("Status")),
            creation_date=_utc(row.get("CreationDate")),
            vault_arn=_text(row.get("BackupVaultArn")),
            vault_type=(
                _STANDARD_VAULT
                if row.get("VaultType") is None
                else _text(row.get("VaultType")) or ""
            ),
            source_vault_arn=(
                None if source_vault_arn is None else _text(source_vault_arn) or ""
            ),
        )

    def could_be_eligible(self, cutoff: datetime, observed_at: datetime) -> bool:
        """Keep recent and undated candidates whose outcome is still possible."""
        if self.status in _INELIGIBLE_STATUS:
            return False
        if self.creation_date is None or self.creation_date > observed_at:
            return True
        return self.creation_date >= cutoff

    def has_unverified_origin(self, scope: Scope) -> bool:
        """Check whether an unidentified volume could originate in the audit scope."""
        if volume_scope(self.source_arn) is not None:
            return False
        source_vault = _vault_identity(self.source_vault_arn)
        return source_vault is None or source_vault[0] == scope

    def is_confirmed(self, vault: Vault, scope: Scope, observed_at: datetime) -> bool:
        """Verify fields required for a candidate to prove recent EBS evidence."""
        return (
            self.resource_type == "EBS"
            and self.vault_arn == vault.arn
            and self.vault_type == _STANDARD_VAULT
            and _valid_point_arn(self.arn, scope)
            and self.status in _ELIGIBLE_STATUS
            and self.creation_date is not None
            and self.creation_date <= observed_at
            and self.source_vault_arn is None
        )


@dataclass(frozen=True)
class Decision:
    """Freshness outcome for an audited volume. SKIP produces no finding."""

    status: Literal["PASS", "FAIL", "SKIP"]
    point: EbsRecoveryPoint | None = None
    reason: str | None = None


class EbsRecoveryEvidence:
    """Keep pre-limit Vault evidence for a single audit."""

    def __init__(self, partition: str, account: str):
        """Initialize Backup evidence and its UTC reference time for the audit.

        This time stays fixed for the audit and anchors both bounds of the
        CreationDate window. Points created later cannot support PASS. If they
        make the evidence uncertain, the check omits the finding. Resource
        states reflect observations made during collection.

        Args:
            partition: The audited AWS partition.
            account: The audited AWS account ID.
        """
        self.partition = partition
        self.account = account
        self.observed_at = datetime.now(timezone.utc)
        self.discovery: dict[str, CollectionResult[VaultDescription]] = {}
        self.standard_vaults: dict[str, frozenset[Vault] | None] = {}
        self.points: dict[Vault, list[CollectionResult[EbsRecoveryPoint]]] = {}
        self._lock = Lock()

    def scope(self, region: str) -> Scope:
        """Return the audited Backup scope for a regional request."""
        return self.partition, self.account, region

    def store_discovery(
        self, region: str, result: CollectionResult[VaultDescription]
    ) -> None:
        """Distinguish confirmed standard vaults from ambiguous discovery."""
        self.discovery[region] = result
        self.standard_vaults[region] = None
        if not result.complete:
            return
        scope = self.scope(region)
        vault_types: dict[Vault, set[str]] = defaultdict(set)
        for record in result.rows:
            identity = _vault_identity(record.arn)
            if identity is None:
                self._unverified_discovery(region)
                return
            vault_scope, name = identity
            if vault_scope != scope:
                continue
            vault = Vault(record.arn, name, region)
            if record.vault_type not in _OTHER_VAULT_TYPES and (
                record.vault_type != _STANDARD_VAULT or record.name != vault.name
            ):
                self._unverified_discovery(region)
                return
            vault_types[vault].add(record.vault_type)

        if any(len(types) > 1 for types in vault_types.values()):
            self._unverified_discovery(region)
            return
        self.standard_vaults[region] = frozenset(
            vault for vault, types in vault_types.items() if _STANDARD_VAULT in types
        )

    def _unverified_discovery(self, region: str) -> None:
        log_unavailable(VAULT_ACTION, self.scope(region), "UnverifiedVaultScope")

    def start_points(self, vault: Vault) -> CollectionResult[EbsRecoveryPoint] | None:
        """Track a Vault read only when its owned standard type was confirmed."""
        if vault not in (self.standard_vaults.get(vault.region) or ()):
            return None
        result = CollectionResult[EbsRecoveryPoint]()
        with self._lock:
            self.points.setdefault(vault, []).append(result)
        return result

    def evaluate(
        self, region: str, targets: Iterable[str], hours: int
    ) -> dict[str, Decision]:
        """Evaluate only the volumes in a fully read standard Vault scope."""
        targets = set(targets)
        vaults = self.standard_vaults.get(region)
        if vaults is None:
            return {
                arn: Decision("SKIP", reason="VaultDiscoveryIncomplete")
                for arn in targets
            }
        if any(
            not self.points.get(vault)
            or not all(result.complete for result in self.points[vault])
            for vault in vaults
        ):
            return {
                arn: Decision("SKIP", reason="VaultPointsIncomplete") for arn in targets
            }

        scope = self.scope(region)
        cutoff = self.observed_at - timedelta(hours=hours)
        affected: set[str] = set()
        latest: dict[str, EbsRecoveryPoint] = {}
        for vault in vaults:
            points: dict[str | EbsRecoveryPoint, set[EbsRecoveryPoint]] = defaultdict(
                set
            )
            for result in self.points[vault]:
                for point in result.rows:
                    points[point.arn or point].add(point)

            for variants in points.values():
                candidates = [
                    point
                    for point in variants
                    if (
                        point.resource_type in (None, "EBS")
                        or volume_scope(point.source_arn)
                    )
                    and point.could_be_eligible(cutoff, self.observed_at)
                ]
                if not candidates:
                    continue
                if any(point.has_unverified_origin(scope) for point in candidates):
                    log_unavailable(
                        POINT_ACTION, scope, "UnverifiedVolumeOrigin", vault.arn
                    )
                    return {
                        arn: Decision("SKIP", reason="UnverifiedVolumeOrigin")
                        for arn in targets
                    }

                matched = {point.source_arn for point in variants} & targets
                if not matched:
                    continue
                point = candidates[0]
                if len(variants) > 1 or not point.is_confirmed(
                    vault, scope, self.observed_at
                ):
                    affected.update(matched)
                    for arn in matched:
                        log_unavailable(
                            POINT_ACTION,
                            scope,
                            "UnverifiedRecoveryPoint",
                            vault.arn,
                            volume_arn=arn,
                        )
                    continue
                arn = next(iter(matched))
                current = latest.get(arn)
                if current is None or (point.creation_date, point.arn) > (
                    current.creation_date,
                    current.arn,
                ):
                    latest[arn] = point

        decisions = {arn: Decision("FAIL") for arn in targets}
        decisions.update(
            {arn: Decision("PASS", point) for arn, point in latest.items()}
        )
        decisions.update(
            {
                arn: Decision("SKIP", reason="UnverifiedRecoveryPoint")
                for arn in affected
            }
        )
        return decisions
