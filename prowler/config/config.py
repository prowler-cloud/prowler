import os
import pathlib
from datetime import datetime, timezone
from enum import Enum
from os import getcwd
from typing import Tuple

import requests
import yaml
from packaging import version

from prowler.lib.logger import logger


class _MutableTimestamp:
    """Lightweight proxy to keep timestamp references in sync across modules."""

    def __init__(self, value: datetime) -> None:
        self.value = value

    def set(self, value: datetime) -> None:
        self.value = value

    def __getattr__(self, name):
        return getattr(self.value, name)

    def __str__(self) -> str:  # pragma: no cover - trivial forwarder
        return str(self.value)

    def __repr__(self) -> str:  # pragma: no cover - trivial forwarder
        return repr(self.value)

    def __eq__(self, other) -> bool:
        if isinstance(other, _MutableTimestamp):
            return self.value == other.value
        return self.value == other


timestamp = _MutableTimestamp(datetime.today())
timestamp_utc = _MutableTimestamp(datetime.now(timezone.utc))
prowler_version = "5.19.0"
html_logo_url = "https://github.com/prowler-cloud/prowler/"
square_logo_img = "https://raw.githubusercontent.com/prowler-cloud/prowler/dc7d2d5aeb92fdf12e8604f42ef6472cd3e8e889/docs/img/prowler-logo-black.png"
aws_logo = "https://user-images.githubusercontent.com/38561120/235953920-3e3fba08-0795-41dc-b480-9bea57db9f2e.png"
azure_logo = "https://user-images.githubusercontent.com/38561120/235927375-b23e2e0f-8932-49ec-b59c-d89f61c8041d.png"
gcp_logo = "https://user-images.githubusercontent.com/38561120/235928332-eb4accdc-c226-4391-8e97-6ca86a91cf50.png"

orange_color = "\033[38;5;208m"
banner_color = "\033[1;92m"


class Provider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    CLOUDFLARE = "cloudflare"
    KUBERNETES = "kubernetes"
    M365 = "m365"
    GITHUB = "github"
    GOOGLEWORKSPACE = "googleworkspace"
    IAC = "iac"
    NHN = "nhn"
    MONGODBATLAS = "mongodbatlas"
    ORACLECLOUD = "oraclecloud"
    ALIBABACLOUD = "alibabacloud"
    OPENSTACK = "openstack"
    IMAGE = "image"


# Providers that delegate scanning to an external tool (e.g. Trivy, promptfoo)
# and bypass standard check/service loading.
EXTERNAL_TOOL_PROVIDERS = frozenset({"iac", "llm", "image"})

# Compliance
actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))


def get_available_compliance_frameworks(provider=None):
    available_compliance_frameworks = []
    providers = [p.value for p in Provider]
    if provider:
        providers = [provider]
    for provider in providers:
        compliance_dir = f"{actual_directory}/../compliance/{provider}"
        if not os.path.isdir(compliance_dir):
            continue
        with os.scandir(compliance_dir) as files:
            for file in files:
                if file.is_file() and file.name.endswith(".json"):
                    available_compliance_frameworks.append(
                        file.name.removesuffix(".json")
                    )
    return available_compliance_frameworks


available_compliance_frameworks = get_available_compliance_frameworks()


# AWS services-regions matrix json
aws_services_json_file = "aws_regions_by_service.json"

# gcp_zones_json_file = "gcp_zones.json"

default_output_directory = getcwd() + "/output"
output_file_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
timestamp_iso = timestamp.isoformat(sep=" ", timespec="seconds")
csv_file_suffix = ".csv"
json_file_suffix = ".json"
json_asff_file_suffix = ".asff.json"
json_ocsf_file_suffix = ".ocsf.json"
html_file_suffix = ".html"
default_config_file_path = (
    f"{pathlib.Path(os.path.dirname(os.path.realpath(__file__)))}/config.yaml"
)
default_fixer_config_file_path = (
    f"{pathlib.Path(os.path.dirname(os.path.realpath(__file__)))}/fixer_config.yaml"
)
default_redteam_config_file_path = (
    f"{pathlib.Path(os.path.dirname(os.path.realpath(__file__)))}/llm_config.yaml"
)
encoding_format_utf_8 = "utf-8"
available_output_formats = ["csv", "json-asff", "json-ocsf", "html"]

# Prowler Cloud API settings
cloud_api_base_url = os.getenv("PROWLER_CLOUD_API_BASE", "https://api.prowler.com")
cloud_api_key = os.getenv("PROWLER_API_KEY", "")
cloud_api_ingestion_path = "/api/v1/ingestions"


def set_output_timestamp(
    new_timestamp: datetime,
) -> Tuple[datetime, datetime, str, str]:
    """
    Override the global output timestamps so generated artifacts reflect a specific scan.
    Returns the previous values so callers can restore them afterwards.
    """
    global timestamp, timestamp_utc, output_file_timestamp, timestamp_iso

    previous_values = (
        timestamp.value,
        timestamp_utc.value,
        output_file_timestamp,
        timestamp_iso,
    )

    timestamp.set(new_timestamp)
    timestamp_utc.set(
        new_timestamp.astimezone(timezone.utc)
        if new_timestamp.tzinfo
        else new_timestamp.replace(tzinfo=timezone.utc)
    )
    output_file_timestamp = timestamp.strftime("%Y%m%d%H%M%S")
    timestamp_iso = timestamp.isoformat(sep=" ", timespec="seconds")

    return previous_values


def get_default_mute_file_path(provider: str):
    """
    get_default_mute_file_path returns the default mute file path for the provider
    """
    # TODO: create default mutelist file for kubernetes, azure and gcp
    mutelist_path = f"{pathlib.Path(os.path.dirname(os.path.realpath(__file__)))}/{provider}_mutelist.yaml"
    if not os.path.isfile(mutelist_path):
        mutelist_path = None
    return mutelist_path


def check_current_version():
    try:
        prowler_version_string = f"Prowler {prowler_version}"
        release_response = requests.get(
            "https://api.github.com/repos/prowler-cloud/prowler/tags", timeout=1
        )
        latest_version = release_response.json()[0]["name"]
        if version.parse(latest_version) > version.parse(prowler_version):
            return f"{prowler_version_string} (latest is {latest_version}, upgrade for the latest features)"
        else:
            return (
                f"{prowler_version_string} (You are running the latest version, yay!)"
            )
    except requests.RequestException:
        return f"{prowler_version_string}"
    except Exception:
        return f"{prowler_version_string}"


def load_and_validate_config_file(provider: str, config_file_path: str) -> dict:
    """
    Reads the Prowler config file in YAML format from the default location or the file passed with the --config-file flag.

    Args:
        provider (str): The provider name (e.g., 'aws', 'gcp', 'azure', 'kubernetes').
        config_file_path (str): The path to the configuration file.

    Returns:
        dict: The configuration dictionary for the specified provider.
    """
    try:
        with open(config_file_path, "r", encoding=encoding_format_utf_8) as f:
            config_file = yaml.safe_load(f)

            # Not to introduce a breaking change, allow the old format config file without any provider keys
            # and a new format with a key for each provider to include their configuration values within.
            if any(
                key in config_file
                for key in ["aws", "gcp", "azure", "kubernetes", "m365"]
            ):
                config = config_file.get(provider, {})
            else:
                config = config_file if config_file else {}
                # Not to break Azure, K8s and GCP does not support or use the old config format
                if provider in ["azure", "gcp", "kubernetes", "m365"]:
                    config = {}

            return config

    except FileNotFoundError as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
    except yaml.YAMLError as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
    except UnicodeDecodeError as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )

    return {}


def load_and_validate_fixer_config_file(
    provider: str, fixer_config_file_path: str
) -> dict:
    """
    Reads the Prowler fixer config file in YAML format from the default location or the file passed with the --fixer-config flag.

    Args:
        provider (str): The provider name (e.g., 'aws', 'gcp', 'azure', 'kubernetes').
        fixer_config_file_path (str): The path to the fixer configuration file.

    Returns:
        dict: The fixer configuration dictionary for the specified provider.
    """
    try:
        with open(fixer_config_file_path, "r", encoding=encoding_format_utf_8) as f:
            fixer_config_file = yaml.safe_load(f)
            return fixer_config_file.get(provider, {})

    except FileNotFoundError as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
    except yaml.YAMLError as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
    except UnicodeDecodeError as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )

    return {}
