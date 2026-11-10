from datetime import datetime
from typing import ClassVar, Optional

from cloudflare import NotFoundError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class Workers(CloudflareService):
    """Retrieve Cloudflare Workers scripts and their security-relevant settings.

    Data that could not be retrieved is tracked per account (``*_failed_accounts``)
    so checks can report it as MANUAL instead of silently omitting it.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.scripts: list["CloudflareWorkerScript"] = []
        self.list_failed_accounts: set[str] = set()
        self.settings_failed_accounts: set[str] = set()
        self.subdomain_failed_accounts: set[str] = set()
        self._list_scripts()
        self.__threading_call__(self._get_script_details, self.scripts)

    def _list_scripts(self) -> None:
        """List Workers scripts for every audited account."""
        logger.info("Workers - Listing Workers scripts...")
        for account_id in self.provider.identity.audited_accounts:
            try:
                scripts = []
                seen_script_ids: set[str] = set()
                for script in self.client.workers.scripts.list(account_id=account_id):
                    script_id = getattr(script, "id", None)
                    if not script_id or script_id in seen_script_ids:
                        continue
                    seen_script_ids.add(script_id)

                    placement = getattr(script, "placement", None)
                    scripts.append(
                        CloudflareWorkerScript(
                            # Script names are only unique within an account.
                            id=f"{account_id}/{script_id}",
                            name=script_id,
                            account_id=account_id,
                            created_on=getattr(script, "created_on", None),
                            modified_on=getattr(script, "modified_on", None),
                            logpush=getattr(script, "logpush", None),
                            placement_mode=getattr(placement, "mode", None)
                            or getattr(script, "placement_mode", None),
                        )
                    )
                self.scripts.extend(scripts)
            except Exception as error:
                self.list_failed_accounts.add(account_id)
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
            self._set_observability(script, getattr(settings, "observability", None))

            # Plain text and JSON bindings are stored unencrypted. Only mark the
            # bindings as known once settings were retrieved successfully, so a
            # failed call is not mistaken for "no bindings".
            plain_text_bindings: dict[str, str] = {}
            for binding in getattr(settings, "bindings", None) or []:
                binding_type = getattr(binding, "type", None)
                binding_name = getattr(binding, "name", None)
                if not binding_name:
                    continue
                if binding_type == "plain_text":
                    plain_text_bindings[binding_name] = (
                        getattr(binding, "text", "") or ""
                    )
                elif binding_type == "json":
                    plain_text_bindings[binding_name] = (
                        getattr(binding, "json_", "") or ""
                    )
            script.plain_text_bindings = plain_text_bindings
        except Exception as error:
            self.settings_failed_accounts.add(script.account_id)
            logger.error(
                f"{script.account_id}/{script.name} settings -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        try:
            subdomain = self.client.workers.scripts.subdomain.get(
                script_name=script.name, account_id=script.account_id
            )
            script.workers_dev_enabled = bool(getattr(subdomain, "enabled", False))
            script.previews_enabled = bool(
                getattr(subdomain, "previews_enabled", False)
            )
        except NotFoundError:
            # The account has no workers.dev subdomain: the script cannot be
            # reached on workers.dev or through Preview URLs.
            script.workers_dev_enabled = False
            script.previews_enabled = False
        except Exception as error:
            self.subdomain_failed_accounts.add(script.account_id)
            logger.error(
                f"{script.account_id}/{script.name} workers.dev subdomain -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _set_observability(script: "CloudflareWorkerScript", observability) -> None:
        """Resolve the effective Workers Logs settings, applying API defaults.

        ``logs.enabled`` and ``logs.head_sampling_rate`` inherit the top-level
        values when omitted; ``invocation_logs`` defaults to true and sampling
        rates default to 1.
        """
        enabled = bool(observability and getattr(observability, "enabled", False))
        logs = getattr(observability, "logs", None) if observability else None
        logs_enabled = getattr(logs, "enabled", None) if logs else None
        invocation_logs = getattr(logs, "invocation_logs", None) if logs else None
        rate = getattr(logs, "head_sampling_rate", None) if logs else None
        if rate is None and observability:
            rate = getattr(observability, "head_sampling_rate", None)

        script.observability_enabled = enabled
        script.observability_logs_enabled = (
            enabled if logs_enabled is None else bool(logs_enabled)
        )
        script.invocation_logs_enabled = (
            True if invocation_logs is None else bool(invocation_logs)
        )
        script.log_sampling_rate = 1.0 if rate is None else float(rate)


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
    invocation_logs_enabled: Optional[bool] = None
    log_sampling_rate: Optional[float] = None
    workers_dev_enabled: Optional[bool] = None
    previews_enabled: Optional[bool] = None
    # Values of plain_text and json bindings. None means they could not be
    # retrieved. Redacted from finding output because they may hold secrets.
    plain_text_bindings: Optional[dict[str, str]] = None
    sensitive_fields: ClassVar[tuple[str, ...]] = ("plain_text_bindings",)
    is_global_resource: ClassVar[bool] = True
