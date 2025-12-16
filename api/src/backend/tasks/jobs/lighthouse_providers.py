from typing import Dict

import boto3
import openai
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from celery.utils.log import get_task_logger

from api.models import LighthouseProviderConfiguration, LighthouseProviderModels

logger = get_task_logger(__name__)

# OpenAI model prefixes to exclude from Lighthouse model selection.
# These models don't support text chat completions and tool calling.
EXCLUDED_OPENAI_MODEL_PREFIXES = (
    "dall-e",  # Image generation
    "whisper",  # Audio transcription
    "tts-",  # Text-to-speech (tts-1, tts-1-hd, etc.)
    "sora",  # Text-to-video (sora-2, sora-2-pro, etc.)
    "text-embedding",  # Embeddings
    "embedding",  # Embeddings (alternative naming)
    "text-moderation",  # Content moderation
    "omni-moderation",  # Content moderation
    "text-davinci",  # Legacy completion models
    "text-curie",  # Legacy completion models
    "text-babbage",  # Legacy completion models
    "text-ada",  # Legacy completion models
    "davinci",  # Legacy completion models
    "curie",  # Legacy completion models
    "babbage",  # Legacy completion models
    "ada",  # Legacy completion models
    "computer-use",  # Computer control agent
    "gpt-image",  # Image generation
    "gpt-audio",  # Audio models
    "gpt-realtime",  # Realtime voice API
)

# OpenAI model substrings to exclude (patterns that can appear anywhere in model ID).
# These patterns identify non-chat model variants.
EXCLUDED_OPENAI_MODEL_SUBSTRINGS = (
    "-audio-",  # Audio preview models (gpt-4o-audio-preview, etc.)
    "-realtime-",  # Realtime preview models (gpt-4o-realtime-preview, etc.)
    "-transcribe",  # Transcription models (gpt-4o-transcribe, etc.)
    "-tts",  # TTS models (gpt-4o-mini-tts)
    "-instruct",  # Legacy instruct models (gpt-3.5-turbo-instruct, etc.)
)


def _extract_error_message(e: Exception) -> str:
    """
    Extract a user-friendly error message from various exception types.

    This function handles exceptions from different providers (OpenAI, AWS Bedrock)
    and extracts the most relevant error message for display to users.

    Args:
        e: The exception to extract a message from.

    Returns:
        str: A user-friendly error message.
    """
    # For OpenAI SDK errors (>= v1.0)
    # OpenAI exceptions have a 'body' attribute with error details
    if hasattr(e, "body") and isinstance(e.body, dict):
        if "message" in e.body:
            return e.body["message"]
        # Sometimes nested under 'error' key
        if "error" in e.body and isinstance(e.body["error"], dict):
            return e.body["error"].get("message", str(e))

    # For boto3 ClientError
    # Boto3 exceptions have a 'response' attribute with error details
    if hasattr(e, "response") and isinstance(e.response, dict):
        error_info = e.response.get("Error", {})
        if error_info.get("Message"):
            return error_info["Message"]

    # Fallback to string representation for unknown error types
    return str(e)


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

    Supports two authentication methods:
    1. AWS access key + secret key + region
    2. Bedrock API key (bearer token) + region

    Args:
        provider_cfg (LighthouseProviderConfiguration): The provider configuration instance
            containing the credentials.

    Returns:
        Dict[str, str] | None: Dictionary with either:
            - 'access_key_id', 'secret_access_key', and 'region' for access key auth
            - 'api_key' and 'region' for API key (bearer token) auth
            Returns None if credentials are invalid or missing.
    """
    creds = provider_cfg.credentials_decoded
    if not isinstance(creds, dict):
        return None

    region = creds.get("region")
    if not isinstance(region, str) or not region:
        return None

    # Check for API key authentication first
    api_key = creds.get("api_key")
    if isinstance(api_key, str) and api_key:
        return {
            "api_key": api_key,
            "region": region,
        }

    # Fall back to access key authentication
    access_key_id = creds.get("access_key_id")
    secret_access_key = creds.get("secret_access_key")

    # Validate all required fields are present and are strings
    if (
        not isinstance(access_key_id, str)
        or not access_key_id
        or not isinstance(secret_access_key, str)
        or not secret_access_key
    ):
        return None

    return {
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
        "region": region,
    }


def _create_bedrock_client(
    bedrock_creds: Dict[str, str], service_name: str = "bedrock"
):
    """
    Create a boto3 Bedrock client with the appropriate authentication method.

    Supports two authentication methods:
    1. API key (bearer token) - uses unsigned requests with Authorization header
    2. AWS access key + secret key - uses standard SigV4 signing

    Args:
        bedrock_creds: Dictionary with either:
            - 'api_key' and 'region' for API key (bearer token) auth
            - 'access_key_id', 'secret_access_key', and 'region' for access key auth
        service_name: The Bedrock service name. Use 'bedrock' for control plane
            operations (list_foundation_models, etc.) or 'bedrock-runtime' for
            inference operations.

    Returns:
        boto3 client configured for the specified Bedrock service.
    """
    region = bedrock_creds["region"]

    if "api_key" in bedrock_creds:
        bearer_token = bedrock_creds["api_key"]
        client = boto3.client(
            service_name=service_name,
            region_name=region,
            config=Config(signature_version=UNSIGNED),
        )

        def inject_bearer_token(request, **kwargs):
            request.headers["Authorization"] = f"Bearer {bearer_token}"

        client.meta.events.register("before-send.*.*", inject_bearer_token)
        return client

    return boto3.client(
        service_name=service_name,
        region_name=region,
        aws_access_key_id=bedrock_creds["access_key_id"],
        aws_secret_access_key=bedrock_creds["secret_access_key"],
    )


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
            bedrock_client = _create_bedrock_client(bedrock_creds)
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

            # Test connection using OpenAI SDK with custom base_url
            # Note: base_url should include version (e.g., https://openrouter.ai/api/v1)
            client = openai.OpenAI(
                api_key=params["api_key"],
                base_url=params["base_url"],
            )
            _ = client.models.list()

        else:
            return {"connected": False, "error": "Unsupported provider type"}

        # Connection successful
        provider_cfg.is_active = True
        provider_cfg.save()
        return {"connected": True, "error": None}

    except Exception as e:
        error_message = _extract_error_message(e)
        logger.warning(
            "%s connection check failed: %s", provider_cfg.provider_type, error_message
        )
        provider_cfg.is_active = False
        provider_cfg.save()
        return {"connected": False, "error": error_message}


def _fetch_openai_models(api_key: str) -> Dict[str, str]:
    """
    Fetch available models from OpenAI API.

    Filters out models that don't support text input/output and tool calling,
    such as image generation (DALL-E), audio transcription (Whisper),
    text-to-speech (TTS), embeddings, and moderation models.

    Args:
        api_key: OpenAI API key for authentication.

    Returns:
        Dict mapping model_id to model_name. For OpenAI, both are the same
        as the API doesn't provide separate display names. Only includes
        models that support text input, text output or tool calling.

    Raises:
        Exception: If the API call fails.
    """
    client = openai.OpenAI(api_key=api_key)
    models = client.models.list()

    # Filter models to only include those supporting chat completions + tool calling
    filtered_models = {}
    for model in getattr(models, "data", []):
        model_id = model.id

        # Skip if model ID starts with excluded prefixes
        if model_id.startswith(EXCLUDED_OPENAI_MODEL_PREFIXES):
            continue

        # Skip if model ID contains excluded substrings
        if any(substring in model_id for substring in EXCLUDED_OPENAI_MODEL_SUBSTRINGS):
            continue

        # Include model (supports chat completions + tool calling)
        filtered_models[model_id] = model_id

    return filtered_models


def _fetch_openai_compatible_models(base_url: str, api_key: str) -> Dict[str, str]:
    """
    Fetch available models from an OpenAI-compatible API using the OpenAI SDK.

    Returns a mapping of model_id -> model_name. Prefers the 'name' attribute
    if available (e.g., from OpenRouter), otherwise falls back to 'id'.

    Note: base_url should include version (e.g., https://openrouter.ai/api/v1)
    """
    client = openai.OpenAI(api_key=api_key, base_url=base_url)
    models = client.models.list()

    available_models: Dict[str, str] = {}
    for model in models.data:
        model_id = model.id
        # Prefer provider-supplied human-friendly name when available
        name = getattr(model, "name", None)
        if name:
            available_models[model_id] = name
        else:
            available_models[model_id] = model_id

    return available_models


def _get_region_prefix(region: str) -> str:
    """
    Determine geographic prefix for AWS region.

    Examples: ap-south-1 -> apac, us-east-1 -> us, eu-west-1 -> eu
    """
    if region.startswith(("us-", "ca-", "sa-")):
        return "us"
    elif region.startswith("eu-"):
        return "eu"
    elif region.startswith("ap-"):
        return "apac"
    return "global"


def _clean_inference_profile_name(profile_name: str) -> str:
    """
    Remove geographic prefix from inference profile name.

    AWS includes geographic prefixes in profile names which are redundant
    since the profile ID already contains this information.

    Examples:
        "APAC Anthropic Claude 3.5 Sonnet" -> "Anthropic Claude 3.5 Sonnet"
        "GLOBAL Claude Sonnet 4.5" -> "Claude Sonnet 4.5"
        "US Anthropic Claude 3 Haiku" -> "Anthropic Claude 3 Haiku"
    """
    prefixes = ["APAC ", "GLOBAL ", "US ", "EU ", "APAC-", "GLOBAL-", "US-", "EU-"]

    for prefix in prefixes:
        if profile_name.upper().startswith(prefix.upper()):
            return profile_name[len(prefix) :].strip()

    return profile_name


def _supports_text_modality(input_modalities: list, output_modalities: list) -> bool:
    """Check if model supports TEXT for both input and output."""
    return "TEXT" in input_modalities and "TEXT" in output_modalities


def _get_foundation_model_modalities(
    bedrock_client, model_id: str
) -> tuple[list, list] | None:
    """
    Fetch input and output modalities for a foundation model.

    Returns:
        (input_modalities, output_modalities) or None if fetch fails
    """
    try:
        model_info = bedrock_client.get_foundation_model(modelIdentifier=model_id)
        model_details = model_info.get("modelDetails", {})
        input_mods = model_details.get("inputModalities", [])
        output_mods = model_details.get("outputModalities", [])
        return (input_mods, output_mods)
    except (BotoCoreError, ClientError) as e:
        logger.debug("Could not fetch model details for %s: %s", model_id, str(e))
        return None


def _extract_foundation_model_ids(profile_models: list) -> list[str]:
    """
    Extract foundation model IDs from inference profile model ARNs.

    Args:
        profile_models: List of model references from inference profile

    Returns:
        List of foundation model IDs extracted from ARNs
    """
    model_ids = []
    for model_ref in profile_models:
        model_arn = model_ref.get("modelArn", "")
        if "foundation-model/" in model_arn:
            model_id = model_arn.split("foundation-model/")[1]
            model_ids.append(model_id)
    return model_ids


def _build_inference_profile_map(
    bedrock_client, region: str
) -> Dict[str, tuple[str, str]]:
    """
    Build map of foundation_model_id -> best inference profile.

    Returns:
        Dict mapping foundation_model_id to (profile_id, profile_name)
        Only includes profiles with TEXT modality support
        Prefers region-matched profiles over others
    """
    region_prefix = _get_region_prefix(region)
    model_to_profile: Dict[str, tuple[str, str]] = {}

    try:
        response = bedrock_client.list_inference_profiles()
        profiles = response.get("inferenceProfileSummaries", [])

        for profile in profiles:
            profile_id = profile.get("inferenceProfileId")
            profile_name = profile.get("inferenceProfileName")

            if not profile_id or not profile_name:
                continue

            profile_models = profile.get("models", [])
            if not profile_models:
                continue

            foundation_model_ids = _extract_foundation_model_ids(profile_models)
            if not foundation_model_ids:
                continue

            modalities = _get_foundation_model_modalities(
                bedrock_client, foundation_model_ids[0]
            )
            if not modalities:
                continue

            input_mods, output_mods = modalities
            if not _supports_text_modality(input_mods, output_mods):
                continue

            is_preferred = profile_id.startswith(f"{region_prefix}.")
            clean_name = _clean_inference_profile_name(profile_name)

            for foundation_model_id in foundation_model_ids:
                if foundation_model_id not in model_to_profile:
                    model_to_profile[foundation_model_id] = (profile_id, clean_name)
                elif is_preferred and not model_to_profile[foundation_model_id][
                    0
                ].startswith(f"{region_prefix}."):
                    model_to_profile[foundation_model_id] = (profile_id, clean_name)

    except (BotoCoreError, ClientError) as e:
        logger.info("Could not fetch inference profiles in %s: %s", region, str(e))

    return model_to_profile


def _check_on_demand_availability(bedrock_client, model_id: str) -> bool:
    """Check if an ON_DEMAND foundation model is entitled and available."""
    try:
        availability = bedrock_client.get_foundation_model_availability(
            modelId=model_id
        )
        entitlement = availability.get("entitlementAvailability")
        return entitlement == "AVAILABLE"
    except (BotoCoreError, ClientError) as e:
        logger.debug("Could not check availability for %s: %s", model_id, str(e))
        return False


def _fetch_bedrock_models(bedrock_creds: Dict[str, str]) -> Dict[str, str]:
    """
    Fetch available models from AWS Bedrock, preferring inference profiles over ON_DEMAND.

    Strategy:
    1. Build map of foundation_model -> best_inference_profile (with TEXT validation)
    2. For each TEXT-capable foundation model:
       - Use inference profile ID if available (preferred - better throughput)
       - Fallback to foundation model ID if only ON_DEMAND available
    3. Verify entitlement for ON_DEMAND models

    Args:
        bedrock_creds: Dict with 'region' and auth credentials

    Returns:
        Dict mapping model_id to model_name. IDs can be:
        - Inference profile IDs (e.g., "apac.anthropic.claude-3-5-sonnet-20240620-v1:0")
        - Foundation model IDs (e.g., "anthropic.claude-3-5-sonnet-20240620-v1:0")
    """
    bedrock_client = _create_bedrock_client(bedrock_creds)
    region = bedrock_creds["region"]

    model_to_profile = _build_inference_profile_map(bedrock_client, region)

    foundation_response = bedrock_client.list_foundation_models()
    model_summaries = foundation_response.get("modelSummaries", [])

    models_to_return: Dict[str, str] = {}
    on_demand_models: set[str] = set()

    for model in model_summaries:
        input_mods = model.get("inputModalities", [])
        output_mods = model.get("outputModalities", [])

        if not _supports_text_modality(input_mods, output_mods):
            continue

        model_id = model.get("modelId")
        model_name = model.get("modelName")

        if not model_id or not model_name:
            continue

        if model_id in model_to_profile:
            profile_id, profile_name = model_to_profile[model_id]
            models_to_return[profile_id] = profile_name
        else:
            inference_types = model.get("inferenceTypesSupported", [])
            if "ON_DEMAND" in inference_types:
                models_to_return[model_id] = model_name
                on_demand_models.add(model_id)

    available_models: Dict[str, str] = {}

    for model_id, model_name in models_to_return.items():
        if model_id in on_demand_models:
            if _check_on_demand_availability(bedrock_client, model_id):
                available_models[model_id] = model_name
        else:
            available_models[model_id] = model_name

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
        error_message = _extract_error_message(e)
        logger.warning(
            "Unexpected error refreshing %s models: %s",
            provider_cfg.provider_type,
            error_message,
        )
        return {"created": 0, "updated": 0, "deleted": 0, "error": error_message}

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
