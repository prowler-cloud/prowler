from typing import Dict, Set

import openai
from celery.utils.log import get_task_logger

from api.models import LighthouseProviderConfiguration, LighthouseProviderModels

logger = get_task_logger(__name__)


def _extract_openai_api_key(
    provider_cfg: LighthouseProviderConfiguration,
) -> str | None:
    """
    Safely extract the OpenAI API key from a provider configuration.

    Args:
        provider_cfg (LighthouseProviderConfiguration): The provider configuration instance
            containing the credentials.

    Returns:
        str | None: The API key string if present and valid, otherwise None.
    """
    creds = provider_cfg.credentials_decoded
    if not isinstance(creds, dict):
        return None
    api_key = creds.get("api_key")
    if not isinstance(api_key, str) or not api_key:
        return None
    return api_key


def check_lighthouse_provider_connection(provider_config_id: str) -> Dict:
    """
    Validate a Lighthouse provider configuration by calling the provider API and
    toggle its active state accordingly.

    Currently supports the OpenAI provider by invoking `models.list` to verify that
    the provided credentials are valid.

    Args:
        provider_config_id (str): The primary key of the `LighthouseProviderConfiguration`
            to validate.

    Returns:
        dict: A result dictionary with the following keys:
            - "connected" (bool): Whether the provider credentials are valid.
            - "error" (str | None): The error message when not connected, otherwise None.

    Side Effects:
        - Updates and persists `is_active` on the `LighthouseProviderConfiguration`.

    Raises:
        LighthouseProviderConfiguration.DoesNotExist: If no configuration exists with the given ID.
    """
    provider_cfg = LighthouseProviderConfiguration.objects.get(pk=provider_config_id)

    # TODO: Add support for other providers
    if (
        provider_cfg.provider_type
        != LighthouseProviderConfiguration.ProviderChoices.OPENAI
    ):
        return {"connected": False, "error": "Unsupported provider type"}

    api_key = _extract_openai_api_key(provider_cfg)
    if not api_key:
        provider_cfg.is_active = False
        provider_cfg.save()
        return {"connected": False, "error": "API key is invalid or missing"}

    try:
        client = openai.OpenAI(api_key=api_key)
        _ = client.models.list()
        provider_cfg.is_active = True
        provider_cfg.save()
        return {"connected": True, "error": None}
    except Exception as e:
        logger.warning("OpenAI connection check failed: %s", str(e))
        provider_cfg.is_active = False
        provider_cfg.save()
        return {"connected": False, "error": str(e)}


def refresh_lighthouse_provider_models(provider_config_id: str) -> Dict:
    """
    Refresh the catalog of models for a Lighthouse provider configuration.

    For the OpenAI provider, this fetches the current list of models, upserts entries
    into `LighthouseProviderModels`, and deletes stale entries no longer returned by
    the provider.

    Args:
        provider_config_id (str): The primary key of the `LighthouseProviderConfiguration`
            whose models should be refreshed.

    Returns:
        dict: A result dictionary with the following keys on success:
            - "created" (int): Number of new model rows created.
            - "updated" (int): Number of existing model rows updated.
            - "deleted" (int): Number of stale model rows removed.
        If an error occurs, the dictionary will contain an "error" (str) field instead.

    Raises:
        LighthouseProviderConfiguration.DoesNotExist: If no configuration exists with the given ID.
    """
    provider_cfg = LighthouseProviderConfiguration.objects.get(pk=provider_config_id)

    if (
        provider_cfg.provider_type
        != LighthouseProviderConfiguration.ProviderChoices.OPENAI
    ):
        return {
            "created": 0,
            "updated": 0,
            "deleted": 0,
            "error": "Unsupported provider type",
        }

    api_key = _extract_openai_api_key(provider_cfg)
    if not api_key:
        return {
            "created": 0,
            "updated": 0,
            "deleted": 0,
            "error": "API key is invalid or missing",
        }

    try:
        client = openai.OpenAI(api_key=api_key)
        models = client.models.list()
        fetched_ids: Set[str] = {m.id for m in getattr(models, "data", [])}
    except Exception as e:  # noqa: BLE001
        logger.warning("OpenAI models refresh failed: %s", str(e))
        return {"created": 0, "updated": 0, "deleted": 0, "error": str(e)}

    created = 0
    updated = 0

    for model_id in fetched_ids:
        obj, was_created = LighthouseProviderModels.objects.update_or_create(
            tenant_id=provider_cfg.tenant_id,
            provider_configuration=provider_cfg,
            model_id=model_id,
            defaults={"default_parameters": {}},
        )
        if was_created:
            created += 1
        else:
            updated += 1

    # Delete stale models not present anymore
    deleted, _ = (
        LighthouseProviderModels.objects.filter(
            tenant_id=provider_cfg.tenant_id, provider_configuration=provider_cfg
        )
        .exclude(model_id__in=fetched_ids)
        .delete()
    )

    return {"created": created, "updated": updated, "deleted": deleted}
