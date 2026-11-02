from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class Workers(CloudflareService):
    """Retrieve Cloudflare Workers scripts and their security-relevant settings."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.scripts: list["CloudflareWorkerScript"] = []
        self._list_scripts()
        self.__threading_call__(self._get_script_details, self.scripts)

    def _list_scripts(self) -> None:
        """List Workers scripts for every audited account."""
        logger.info("Workers - Listing Workers scripts...")
        for account_id in self.provider.identity.audited_accounts:
            try:
                seen_script_ids: set[str] = set()
                for script in self.client.workers.scripts.list(account_id=account_id):
                    script_id = getattr(script, "id", None)
                    if not script_id or script_id in seen_script_ids:
                        continue
                    seen_script_ids.add(script_id)

                    placement = getattr(script, "placement", None)
                    self.scripts.append(
                        CloudflareWorkerScript(
                            id=script_id,
                            name=script_id,
                            account_id=account_id,
                            created_on=getattr(script, "created_on", None),
                            modified_on=getattr(script, "modified_on", None),
                            logpush=getattr(script, "logpush", None),
                            placement_mode=getattr(placement, "mode", None)
                            or getattr(script, "placement_mode", None),
                        )
                    )
            except Exception as error:
                logger.error(
                    f"{account_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _get_script_details(self, script: "CloudflareWorkerScript") -> None:
        """Populate settings, bindings and public URL exposure for a script."""
        try:
            settings = self.client.workers.scripts.script_and_version_settings.get(
                script_name=script.name, account_id=script.account_id
            )
            script.compatibility_date = getattr(settings, "compatibility_date", None)
            logpush = getattr(settings, "logpush", None)
            if logpush is not None:
                script.logpush = logpush

            observability = getattr(settings, "observability", None)
            script.observability_enabled = bool(
                observability and getattr(observability, "enabled", False)
            )
            logs = getattr(observability, "logs", None) if observability else None
            # When "logs" is not explicitly configured, Workers Logs follow the
            # top-level observability "enabled" flag.
            script.observability_logs_enabled = (
                bool(getattr(logs, "enabled", False))
                if logs is not None
                else script.observability_enabled
            )

            for binding in getattr(settings, "bindings", None) or []:
                if getattr(binding, "type", None) == "plain_text":
                    binding_name = getattr(binding, "name", None)
                    if binding_name:
                        script.plain_text_bindings[binding_name] = (
                            getattr(binding, "text", "") or ""
                        )
        except Exception as error:
            logger.error(
                f"{script.account_id}/{script.name} settings -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        try:
            subdomain = self.client.workers.scripts.subdomain.get(
                script_name=script.name, account_id=script.account_id
            )
            script.workers_dev_enabled = getattr(subdomain, "enabled", None)
            script.previews_enabled = getattr(subdomain, "previews_enabled", None)
        except Exception as error:
            # Accounts without a registered workers.dev subdomain return an error here.
            logger.warning(
                f"{script.account_id}/{script.name} workers.dev subdomain -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class CloudflareWorkerScript(BaseModel):
    """Cloudflare Workers script representation."""

    id: str
    name: str
    account_id: str
    created_on: Optional[datetime] = None
    modified_on: Optional[datetime] = None
    logpush: Optional[bool] = None
    placement_mode: Optional[str] = None
    compatibility_date: Optional[str] = None
    observability_enabled: Optional[bool] = None
    observability_logs_enabled: Optional[bool] = None
    workers_dev_enabled: Optional[bool] = None
    previews_enabled: Optional[bool] = None
    plain_text_bindings: dict[str, str] = Field(default_factory=dict)
