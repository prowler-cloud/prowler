"""ASPM (Agent Security Posture Management) Provider.

Reads an agent manifest file (YAML or JSON) that describes the security
configuration of deployed AI agents and exposes the parsed agent list to the
check engine.

Manifest format (YAML):

    agents:
      - id: agent-001
        name: agent-docrecommender-prod
        environment: prod          # prod | staging | dev
        cloud_provider: aws        # aws | azure | gcp
        region: us-east-1

        identity:
          type: iam_role
          arn: arn:aws:iam::123456789012:role/agent-docrecommender-prod
          tags:
            agent: "true"
            owner: team-ai
            env: prod
            purpose: document-recommendation
          created_at: "2025-01-15"
          last_used: "2026-03-01"
          uses_oidc: true
          uses_static_credentials: false
          credential_age_days: 45
          rotation_policy_days: 90
          naming_compliant: true
          has_owner_tag: true
          session_duration_seconds: 3600

        permissions:
          has_wildcard_actions: false
          has_admin_policy: false
          has_permission_boundary: true
          shares_role_with_human: false
          data_domains_accessed: ["s3"]

        credentials:
          uses_secrets_manager: true
          has_hardcoded_secrets: false
          rotation_interval_days: 30
          credentials_per_environment: true

        network:
          uses_https_only: true
          has_egress_filtering: true
          has_rate_limiting: true
          validates_tls_certificates: true

        data_access:
          accesses_pii: false
          data_encrypted_at_rest: true
          data_encrypted_in_transit: true

        runtime:
          runs_as_root: false
          privileged_container: false
          has_resource_limits: true
          image_scanned_for_cves: true

        supply_chain:
          framework_cves_scanned: true
          dependencies_version_pinned: true
          artifacts_signed: true

        observability:
          execution_logs_complete: true
          audit_logs_immutable: true
          security_event_alerting: true

        compliance:
          owasp_llm_top10_assessed: true
          incident_response_plan_exists: true

        attack_paths:
          cross_cloud_escalation_possible: false
          compromise_enables_full_account_takeover: false
"""

import json
import sys
from typing import List, Optional

import yaml
from colorama import Fore, Style

from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.aspm.exceptions.exceptions import (
    ASPMManifestInvalidError,
    ASPMManifestNotFoundError,
    ASPMNoAgentsFoundError,
)
from prowler.providers.aspm.models import AgentConfig
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class AspmProvider(Provider):
    """Provider for AI Agent Security Posture Management (ASPM).

    Parses an agent manifest file and exposes the list of agent configurations
    to the check engine.

    Attributes:
        _type: Provider type identifier ("aspm").
        manifest_path: Path to the agent manifest file.
        agents: Parsed and validated list of AgentConfig objects.
        environment_filter: Optional environment filter (prod/staging/dev).
        cloud_provider_filter: Optional cloud provider filter (aws/azure/gcp).
        audit_metadata: Prowler audit metadata.
    """

    _type: str = "aspm"
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        manifest_path: str = "aspm-manifest.yaml",
        environment: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        config_path: Optional[str] = None,
        config_content: Optional[dict] = None,
        fixer_config: dict = {},
        provider_uid: Optional[str] = None,
    ) -> None:
        """Initialise the ASPM provider.

        Args:
            manifest_path: Path to the YAML/JSON agent manifest file.
            environment: Optional filter — only assess agents in this env.
            cloud_provider: Optional filter — only assess agents on this cloud.
            config_path: Prowler global config file path.
            config_content: Prowler global config as a dict.
            fixer_config: Fixer configuration.
            provider_uid: Unique identifier for push-to-cloud integration.
        """
        logger.info("Instantiating ASPM Provider...")

        self.manifest_path = manifest_path
        self.environment_filter = environment
        self.cloud_provider_filter = cloud_provider
        self._provider_uid = provider_uid
        self._session = None
        self._identity = "prowler"
        self._auth_method = "No auth"
        self.region = "global"
        self.audited_account = "local-aspm"

        # Load and parse the manifest
        self.agents: List[AgentConfig] = self._load_manifest()

        # Audit config
        from prowler.config.config import (
            default_config_file_path,
            load_and_validate_config_file,
        )

        if config_content:
            self._audit_config = config_content
        elif config_path and config_path != default_config_file_path:
            self._audit_config = load_and_validate_config_file(self._type, config_path)
        else:
            self._audit_config = {}

        self._fixer_config = fixer_config
        self._mutelist = None

        self.audit_metadata = Audit_Metadata(
            provider=self._type,
            account_id=self.audited_account,
            account_name="aspm",
            region=self.region,
            services_scanned=0,
            expected_checks=[],
            completed_checks=0,
            audit_progress=0,
        )

        Provider.set_global_provider(self)

    # ------------------------------------------------------------------
    # Provider interface (abstract method implementations)
    # ------------------------------------------------------------------

    @property
    def type(self) -> str:
        """Provider type identifier."""
        return self._type

    @property
    def identity(self) -> str:
        """Provider identity string."""
        return self._identity

    @property
    def session(self):
        """ASPM provider has no cloud session."""
        return self._session

    @property
    def audit_config(self) -> dict:
        """Prowler audit configuration."""
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        """Fixer configuration."""
        return self._fixer_config

    @property
    def auth_method(self) -> str:
        """Authentication method description."""
        return self._auth_method

    def setup_session(self) -> None:
        """ASPM provider does not require a cloud session."""

    def print_credentials(self) -> None:
        """Display provider summary in the CLI output."""
        report_title = (
            f"{Style.BRIGHT}Scanning AI Agent Security Posture:{Style.RESET_ALL}"
        )
        report_lines = [
            f"Manifest: {Fore.YELLOW}{self.manifest_path}{Style.RESET_ALL}",
            f"Agents loaded: {Fore.YELLOW}{len(self.agents)}{Style.RESET_ALL}",
        ]
        if self.environment_filter:
            report_lines.append(
                f"Environment filter: {Fore.YELLOW}{self.environment_filter}{Style.RESET_ALL}"
            )
        if self.cloud_provider_filter:
            report_lines.append(
                f"Cloud provider filter: {Fore.YELLOW}{self.cloud_provider_filter}{Style.RESET_ALL}"
            )
        print_boxes(report_lines, report_title)

    # ------------------------------------------------------------------
    # Manifest loading
    # ------------------------------------------------------------------

    def _load_manifest(self) -> List[AgentConfig]:
        """Load and parse the agent manifest file.

        Returns:
            A list of validated AgentConfig objects.

        Raises:
            SystemExit: On unrecoverable manifest errors.
        """
        import os

        if not os.path.exists(self.manifest_path):
            logger.critical(ASPMManifestNotFoundError(self.manifest_path).message)
            sys.exit(1)

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as fh:
                if self.manifest_path.endswith(".json"):
                    raw = json.load(fh)
                else:
                    raw = yaml.safe_load(fh)
        except Exception as exc:
            logger.critical(
                ASPMManifestInvalidError(self.manifest_path, str(exc)).message
            )
            sys.exit(1)

        if not isinstance(raw, dict) or "agents" not in raw:
            logger.critical(
                ASPMManifestInvalidError(
                    self.manifest_path,
                    "Root key 'agents' not found. "
                    "The manifest must contain a top-level 'agents' list.",
                ).message
            )
            sys.exit(1)

        raw_agents = raw.get("agents", [])
        if not raw_agents:
            logger.critical(ASPMNoAgentsFoundError().message)
            sys.exit(1)

        agents: List[AgentConfig] = []
        for entry in raw_agents:
            try:
                agent = AgentConfig(**entry)
                # Apply optional filters
                if (
                    self.environment_filter
                    and agent.environment != self.environment_filter
                ):
                    continue
                if (
                    self.cloud_provider_filter
                    and agent.cloud_provider != self.cloud_provider_filter
                ):
                    continue
                agents.append(agent)
            except Exception as exc:
                agent_id = entry.get("id", "<unknown>")
                logger.error(
                    f"Skipping agent '{agent_id}' — manifest validation error: {exc}"
                )

        if not agents:
            logger.warning(
                "No agents matched the specified filters. "
                "The assessment will produce no findings."
            )

        logger.info(f"Loaded {len(agents)} agent(s) from {self.manifest_path}")
        return agents
