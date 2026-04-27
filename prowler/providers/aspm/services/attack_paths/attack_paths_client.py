"""ASPM Attack Paths service client singleton."""

from prowler.providers.aspm.services.attack_paths.attack_paths_service import (
    AttackPaths,
)

attack_paths_client = AttackPaths
