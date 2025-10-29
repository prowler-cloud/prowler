from typing import Dict

import boto3
import openai
import requests
from botocore.exceptions import BotoCoreError, ClientError
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


def _extract_openai_compatible_params(
    provider_cfg: LighthouseProviderConfiguration,
) -> Dict[str, str] | None:
    """
    Extract base_url and api_key for OpenAI-compatible providers.
    """
    creds = provider_cfg.credentials_decoded
    base_url = provider_cfg.base_url
    if not isinstance(creds, dict):
        return None
    api_key = creds.get("api_key")
    if not isinstance(api_key, str) or not api_key:
        return None
    if not isinstance(base_url, str) or not base_url:
        return None
    return {"base_url": base_url, "api_key": api_key}


def _extract_bedrock_credentials(
    provider_cfg: LighthouseProviderConfiguration,
) -> Dict[str, str] | None:
    """
    Safely extract AWS Bedrock credentials from a provider configuration.

    Args:
        provider_cfg (LighthouseProviderConfiguration): The provider configuration instance
            containing the credentials.

    Returns:
        Dict[str, str] | None: Dictionary with 'access_key_id', 'secret_access_key', and
            'region' if present and valid, otherwise None.
    """
    creds = provider_cfg.credentials_decoded
    if not isinstance(creds, dict):
        return None

    access_key_id = creds.get("access_key_id")
    secret_access_key = creds.get("secret_access_key")
    region = creds.get("region")

    # Validate all required fields are present and are strings
    if (
        not isinstance(access_key_id, str)
        or not access_key_id
        or not isinstance(secret_access_key, str)
        or not secret_access_key
        or not isinstance(region, str)
        or not region
    ):
        return None

    return {
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
        "region": region,
    }


def check_lighthouse_provider_connection(provider_config_id: str) -> Dict:
    """
    Validate a Lighthouse provider configuration by calling the provider API and
    toggle its active state accordingly.

    Args:
        provider_config_id: The primary key of the `LighthouseProviderConfiguration`
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

    try:
        if (
            provider_cfg.provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI
        ):
            api_key = _extract_openai_api_key(provider_cfg)
            if not api_key:
                provider_cfg.is_active = False
                provider_cfg.save()
                return {"connected": False, "error": "API key is invalid or missing"}

            # Test connection by listing models
            client = openai.OpenAI(api_key=api_key)
            _ = client.models.list()

        elif (
            provider_cfg.provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK
        ):
            bedrock_creds = _extract_bedrock_credentials(provider_cfg)
            if not bedrock_creds:
                provider_cfg.is_active = False
                provider_cfg.save()
                return {
                    "connected": False,
                    "error": "AWS credentials are invalid or missing",
                }

            # Test connection by listing foundation models
            bedrock_client = boto3.client(
                "bedrock",
                aws_access_key_id=bedrock_creds["access_key_id"],
                aws_secret_access_key=bedrock_creds["secret_access_key"],
                region_name=bedrock_creds["region"],
            )
            _ = bedrock_client.list_foundation_models()

        elif (
            provider_cfg.provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI_COMPATIBLE
        ):
            params = _extract_openai_compatible_params(provider_cfg)
            if not params:
                provider_cfg.is_active = False
                provider_cfg.save()
                return {
                    "connected": False,
                    "error": "Base URL or API key is invalid or missing",
                }

            # Test connection by hitting the models endpoint
            # Note: base_url should include version (e.g., https://openrouter.ai/api/v1)
            headers = {"Authorization": f"Bearer {params['api_key']}"}
            try:
                resp = requests.get(
                    f"{params['base_url'].rstrip('/')}/models",
                    headers=headers,
                    timeout=15,
                )
                if resp.status_code >= 400:
                    raise Exception(f"HTTP {resp.status_code}: {resp.text[:200]}")

                # Verify the response content type is application/json
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" not in content_type:
                    raise Exception(
                        f"Invalid content type: expected 'application/json', got '{content_type}'"
                    )
            except Exception as e:
                provider_cfg.is_active = False
                provider_cfg.save()
                return {"connected": False, "error": str(e)}

        else:
            return {"connected": False, "error": "Unsupported provider type"}

        # Connection successful
        provider_cfg.is_active = True
        provider_cfg.save()
        return {"connected": True, "error": None}

    except Exception as e:
        logger.warning(
            "%s connection check failed: %s", provider_cfg.provider_type, str(e)
        )
        provider_cfg.is_active = False
        provider_cfg.save()
        return {"connected": False, "error": str(e)}


def _fetch_openai_models(api_key: str) -> Dict[str, str]:
    """
    Fetch available models from OpenAI API.

    Args:
        api_key: OpenAI API key for authentication.

    Returns:
        Dict mapping model_id to model_name. For OpenAI, both are the same
        as the API doesn't provide separate display names.

    Raises:
        Exception: If the API call fails.
    """
    client = openai.OpenAI(api_key=api_key)
    models = client.models.list()
    # OpenAI uses model.id for both ID and display name
    return {m.id: m.id for m in getattr(models, "data", [])}


def _fetch_openai_compatible_models(base_url: str, api_key: str) -> Dict[str, str]:
    """
    Fetch available models from an OpenAI-compatible API.

    Returns a mapping of model_id -> model_name. If the provider doesn't expose
    a models catalog, returns an empty dict.

    Note: base_url should include version (e.g., https://openrouter.ai/api/v1)
    """
    headers = {"Authorization": f"Bearer {api_key}"}
    url = f"{base_url.rstrip('/')}/models"
    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code >= 400:
        raise Exception(f"HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json() if resp.content else {}
    items = data.get("data", []) if isinstance(data, dict) else []

    available_models: Dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        model_id = item.get("id")
        if not isinstance(model_id, str) or not model_id:
            continue

        # Prefer provider-supplied human-friendly name when available
        name_value = item.get("name")
        if isinstance(name_value, str) and name_value:
            available_models[model_id] = name_value
        else:
            available_models[model_id] = model_id

    return available_models


def _fetch_bedrock_models(bedrock_creds: Dict[str, str]) -> Dict[str, str]:
    """
    Fetch available models from AWS Bedrock with entitlement verification.

    This function:
    1. Lists foundation models with TEXT modality support
    2. Lists inference profiles with TEXT modality support
    3. Verifies user has entitlement access to each model

    Args:
        bedrock_creds: Dictionary with 'access_key_id', 'secret_access_key', and 'region'.

    Returns:
        Dict mapping model_id to model_name for all accessible models.

    Raises:
        BotoCoreError, ClientError: If AWS API calls fail.
    """
    bedrock_client = boto3.client(
        "bedrock",
        aws_access_key_id=bedrock_creds["access_key_id"],
        aws_secret_access_key=bedrock_creds["secret_access_key"],
        region_name=bedrock_creds["region"],
    )

    models_to_check: Dict[str, str] = {}

    # Step 1: Get foundation models with TEXT modality
    foundation_response = bedrock_client.list_foundation_models()
    model_summaries = foundation_response.get("modelSummaries", [])

    for model in model_summaries:
        # Check if model supports TEXT input and output modality
        input_modalities = model.get("inputModalities", [])
        output_modalities = model.get("outputModalities", [])

        if "TEXT" not in input_modalities or "TEXT" not in output_modalities:
            continue

        model_id = model.get("modelId")
        if not model_id:
            continue

        inference_types = model.get("inferenceTypesSupported", [])

        # Only include models with ON_DEMAND inference support
        if "ON_DEMAND" in inference_types:
            models_to_check[model_id] = model["modelName"]

    # Step 2: Get inference profiles
    try:
        inference_profiles_response = bedrock_client.list_inference_profiles()
        inference_profiles = inference_profiles_response.get(
            "inferenceProfileSummaries", []
        )

        for profile in inference_profiles:
            # Check if profile supports TEXT modality
            input_modalities = profile.get("inputModalities", [])
            output_modalities = profile.get("outputModalities", [])

            if "TEXT" not in input_modalities or "TEXT" not in output_modalities:
                continue

            profile_id = profile.get("inferenceProfileId")
            if profile_id:
                models_to_check[profile_id] = profile["inferenceProfileName"]

    except (BotoCoreError, ClientError) as e:
        logger.info(
            "Could not fetch inference profiles in %s: %s",
            bedrock_creds["region"],
            str(e),
        )

    # Step 3: Verify entitlement availability for each model
    available_models: Dict[str, str] = {}

    for model_id, model_name in models_to_check.items():
        try:
            availability = bedrock_client.get_foundation_model_availability(
                modelId=model_id
            )

            entitlement = availability.get("entitlementAvailability")

            # Only include models user has access to
            if entitlement == "AVAILABLE":
                available_models[model_id] = model_name
            else:
                logger.debug(
                    "Skipping model %s - entitlement status: %s", model_id, entitlement
                )

        except (BotoCoreError, ClientError) as e:
            logger.debug(
                "Could not check availability for model %s: %s", model_id, str(e)
            )
            continue

    return available_models


def refresh_lighthouse_provider_models(provider_config_id: str) -> Dict:
    """
    Refresh the catalog of models for a Lighthouse provider configuration.

    Fetches the current list of models from the provider, upserts entries into
    `LighthouseProviderModels`, and deletes stale entries no longer returned.

    Args:
        provider_config_id: The primary key of the `LighthouseProviderConfiguration`
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
    fetched_models: Dict[str, str] = {}

    # Fetch models from the appropriate provider
    try:
        if (
            provider_cfg.provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI
        ):
            api_key = _extract_openai_api_key(provider_cfg)
            if not api_key:
                return {
                    "created": 0,
                    "updated": 0,
                    "deleted": 0,
                    "error": "API key is invalid or missing",
                }
            fetched_models = _fetch_openai_models(api_key)

        elif (
            provider_cfg.provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK
        ):
            bedrock_creds = _extract_bedrock_credentials(provider_cfg)
            if not bedrock_creds:
                return {
                    "created": 0,
                    "updated": 0,
                    "deleted": 0,
                    "error": "AWS credentials are invalid or missing",
                }
            fetched_models = _fetch_bedrock_models(bedrock_creds)

        elif (
            provider_cfg.provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI_COMPATIBLE
        ):
            params = _extract_openai_compatible_params(provider_cfg)
            if not params:
                return {
                    "created": 0,
                    "updated": 0,
                    "deleted": 0,
                    "error": "Base URL or API key is invalid or missing",
                }
            fetched_models = _fetch_openai_compatible_models(
                params["base_url"], params["api_key"]
            )

        else:
            return {
                "created": 0,
                "updated": 0,
                "deleted": 0,
                "error": "Unsupported provider type",
            }

    except Exception as e:
        logger.warning(
            "Unexpected error refreshing %s models: %s",
            provider_cfg.provider_type,
            str(e),
        )
        return {"created": 0, "updated": 0, "deleted": 0, "error": str(e)}

    # Upsert models into the catalog
    created = 0
    updated = 0

    for model_id, model_name in fetched_models.items():
        obj, was_created = LighthouseProviderModels.objects.update_or_create(
            tenant_id=provider_cfg.tenant_id,
            provider_configuration=provider_cfg,
            model_id=model_id,
            defaults={
                "model_name": model_name,
                "default_parameters": {},
            },
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
        .exclude(model_id__in=fetched_models.keys())
        .delete()
    )

    return {"created": created, "updated": updated, "deleted": deleted}
