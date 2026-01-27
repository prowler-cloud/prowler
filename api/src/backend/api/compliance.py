from collections.abc import Iterable, Mapping

from api.models import Provider
from prowler.config.config import get_available_compliance_frameworks
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.check.models import CheckMetadata

AVAILABLE_COMPLIANCE_FRAMEWORKS = {}


class LazyComplianceTemplate(Mapping):
    """Lazy-load compliance templates per provider on first access."""

    def __init__(self, provider_types: Iterable[str] | None = None) -> None:
        if provider_types is None:
            provider_types = Provider.ProviderChoices.values
        self._provider_types = tuple(provider_types)
        self._provider_types_set = set(self._provider_types)
        self._cache: dict[str, dict] = {}

    def _load_provider(self, provider_type: str) -> dict:
        if provider_type not in self._provider_types_set:
            raise KeyError(provider_type)
        cached = self._cache.get(provider_type)
        if cached is not None:
            return cached
        _ensure_provider_loaded(provider_type)
        return self._cache[provider_type]

    def __getitem__(self, key: str) -> dict:
        return self._load_provider(key)

    def __iter__(self):
        return iter(self._provider_types)

    def __len__(self) -> int:
        return len(self._provider_types)

    def __contains__(self, key: object) -> bool:
        return key in self._provider_types_set

    def get(self, key: str, default=None):
        if key not in self._provider_types_set:
            return default
        return self._load_provider(key)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        loaded = ", ".join(sorted(self._cache))
        return f"{self.__class__.__name__}(loaded=[{loaded}])"


class LazyChecksMapping(Mapping):
    """Lazy-load checks mapping per provider on first access."""

    def __init__(self, provider_types: Iterable[str] | None = None) -> None:
        if provider_types is None:
            provider_types = Provider.ProviderChoices.values
        self._provider_types = tuple(provider_types)
        self._provider_types_set = set(self._provider_types)
        self._cache: dict[str, dict] = {}

    def _load_provider(self, provider_type: str) -> dict:
        if provider_type not in self._provider_types_set:
            raise KeyError(provider_type)
        cached = self._cache.get(provider_type)
        if cached is not None:
            return cached
        _ensure_provider_loaded(provider_type)
        return self._cache[provider_type]

    def __getitem__(self, key: str) -> dict:
        return self._load_provider(key)

    def __iter__(self):
        return iter(self._provider_types)

    def __len__(self) -> int:
        return len(self._provider_types)

    def __contains__(self, key: object) -> bool:
        return key in self._provider_types_set

    def get(self, key: str, default=None):
        if key not in self._provider_types_set:
            return default
        return self._load_provider(key)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        loaded = ", ".join(sorted(self._cache))
        return f"{self.__class__.__name__}(loaded=[{loaded}])"


PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE = LazyComplianceTemplate()
PROWLER_CHECKS = LazyChecksMapping()


def get_compliance_frameworks(provider_type: Provider.ProviderChoices) -> list[str]:
    """
    Retrieve and cache the list of available compliance frameworks for a specific cloud provider.

    This function lazily loads and caches the available compliance frameworks (e.g., CIS, MITRE, ISO)
    for each provider type (AWS, Azure, GCP, etc.) on first access. Subsequent calls for the same
    provider will return the cached result.

    Args:
        provider_type (Provider.ProviderChoices): The cloud provider type for which to retrieve
            available compliance frameworks (e.g., "aws", "azure", "gcp", "m365").

    Returns:
        list[str]: A list of framework identifiers (e.g., "cis_1.4_aws", "mitre_attack_azure") available
        for the given provider.
    """
    global AVAILABLE_COMPLIANCE_FRAMEWORKS
    if provider_type not in AVAILABLE_COMPLIANCE_FRAMEWORKS:
        AVAILABLE_COMPLIANCE_FRAMEWORKS[provider_type] = (
            get_available_compliance_frameworks(provider_type)
        )

    return AVAILABLE_COMPLIANCE_FRAMEWORKS[provider_type]


def get_prowler_provider_checks(provider_type: Provider.ProviderChoices):
    """
    Retrieve all check IDs for the specified provider type.

    This function fetches the check metadata for the given cloud provider
    and returns an iterable of check IDs.

    Args:
        provider_type (Provider.ProviderChoices): The provider type
            (e.g., 'aws', 'azure') for which to retrieve check IDs.

    Returns:
        Iterable[str]: An iterable of check IDs associated with the specified provider type.
    """
    return CheckMetadata.get_bulk(provider_type).keys()


def get_prowler_provider_compliance(provider_type: Provider.ProviderChoices) -> dict:
    """
    Retrieve the Prowler compliance data for a specified provider type.

    This function fetches the compliance frameworks and their associated
    requirements for the given cloud provider.

    Args:
        provider_type (Provider.ProviderChoices): The provider type
            (e.g., 'aws', 'azure') for which to retrieve compliance data.

    Returns:
        dict: A dictionary mapping compliance framework names to their respective
            Compliance objects for the specified provider.
    """
    return Compliance.get_bulk(provider_type)


def _load_provider_assets(provider_type: Provider.ProviderChoices) -> tuple[dict, dict]:
    prowler_compliance = {provider_type: get_prowler_provider_compliance(provider_type)}
    template = generate_compliance_overview_template(
        prowler_compliance, provider_types=[provider_type]
    )
    checks = load_prowler_checks(prowler_compliance, provider_types=[provider_type])
    return template.get(provider_type, {}), checks.get(provider_type, {})


def _ensure_provider_loaded(provider_type: Provider.ProviderChoices) -> None:
    if (
        provider_type in PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE._cache
        and provider_type in PROWLER_CHECKS._cache
    ):
        return
    template_cached = PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE._cache.get(provider_type)
    checks_cached = PROWLER_CHECKS._cache.get(provider_type)
    if template_cached is not None and checks_cached is not None:
        return
    template, checks = _load_provider_assets(provider_type)
    if template_cached is None:
        PROWLER_COMPLIANCE_OVERVIEW_TEMPLATE._cache[provider_type] = template
    if checks_cached is None:
        PROWLER_CHECKS._cache[provider_type] = checks


def load_prowler_checks(
    prowler_compliance, provider_types: Iterable[str] | None = None
):
    """
    Generate a mapping of checks to the compliance frameworks that include them.

    This function processes the provided compliance data and creates a dictionary
    mapping each provider type to a dictionary where each check ID maps to a set
    of compliance names that include that check.

    Args:
        prowler_compliance (dict): The compliance data for provider types,
            as returned by `get_prowler_provider_compliance`.
        provider_types (Iterable[str] | None): Optional subset of provider types to
            process. Defaults to all providers.

    Returns:
        dict: A nested dictionary where the first-level keys are provider types,
            and the values are dictionaries mapping check IDs to sets of compliance names.
    """
    checks = {}
    if provider_types is None:
        provider_types = Provider.ProviderChoices.values
    for provider_type in provider_types:
        checks[provider_type] = {
            check_id: set() for check_id in get_prowler_provider_checks(provider_type)
        }
        for compliance_name, compliance_data in prowler_compliance.get(
            provider_type, {}
        ).items():
            for requirement in compliance_data.Requirements:
                for check in requirement.Checks:
                    try:
                        checks[provider_type][check].add(compliance_name)
                    except KeyError:
                        continue
    return checks


def generate_scan_compliance(
    compliance_overview, provider_type: str, check_id: str, status: str
):
    """
    Update the compliance overview with the status of a specific check.

    This function updates the compliance overview by setting the status of the given check
    within all compliance frameworks and requirements that include it. It then updates the
    requirement status to 'FAIL' if any of its checks have failed, and adjusts the counts
    of passed and failed requirements in the compliance overview.

    Args:
        compliance_overview (dict): The compliance overview data structure to update.
        provider_type (str): The provider type (e.g., 'aws', 'azure') associated with the check.
        check_id (str): The identifier of the check whose status is being updated.
        status (str): The status of the check (e.g., 'PASS', 'FAIL', 'MUTED').

    Returns:
        None: This function modifies the compliance_overview in place.
    """

    for compliance_id in PROWLER_CHECKS[provider_type][check_id]:
        for requirement in compliance_overview[compliance_id]["requirements"].values():
            if check_id in requirement["checks"]:
                requirement["checks"][check_id] = status
                requirement["checks_status"][status.lower()] += 1

                if requirement["status"] != "FAIL" and any(
                    value == "FAIL" for value in requirement["checks"].values()
                ):
                    requirement["status"] = "FAIL"
                    compliance_overview[compliance_id]["requirements_status"][
                        "passed"
                    ] -= 1
                    compliance_overview[compliance_id]["requirements_status"][
                        "failed"
                    ] += 1


def generate_compliance_overview_template(
    prowler_compliance: dict, provider_types: Iterable[str] | None = None
):
    """
    Generate a compliance overview template for all provider types.

    This function creates a nested dictionary structure representing the compliance
    overview template for each provider type, compliance framework, and requirement.
    It initializes the status of all checks and requirements, and calculates initial
    counts for requirements status.

    Args:
        prowler_compliance (dict): The compliance data for provider types,
            as returned by `get_prowler_provider_compliance`.
        provider_types (Iterable[str] | None): Optional subset of provider types to
            process. Defaults to all providers.

    Returns:
        dict: A nested dictionary representing the compliance overview template,
            structured by provider type and compliance framework.
    """
    template = {}
    if provider_types is None:
        provider_types = Provider.ProviderChoices.values
    for provider_type in provider_types:
        provider_compliance = template.setdefault(provider_type, {})
        compliance_data_dict = prowler_compliance.get(provider_type, {})

        for compliance_name, compliance_data in compliance_data_dict.items():
            compliance_requirements = {}
            requirements_status = {"passed": 0, "failed": 0, "manual": 0}
            total_requirements = 0

            for requirement in compliance_data.Requirements:
                total_requirements += 1
                total_checks = len(requirement.Checks)
                checks_dict = {check: None for check in requirement.Checks}

                req_status_val = "MANUAL" if total_checks == 0 else "PASS"

                # Build requirement dictionary
                requirement_dict = {
                    "name": requirement.Name or requirement.Id,
                    "description": requirement.Description,
                    "tactics": getattr(requirement, "Tactics", []),
                    "subtechniques": getattr(requirement, "SubTechniques", []),
                    "platforms": getattr(requirement, "Platforms", []),
                    "technique_url": getattr(requirement, "TechniqueURL", ""),
                    "attributes": [
                        dict(attribute) for attribute in requirement.Attributes
                    ],
                    "checks": checks_dict,
                    "checks_status": {
                        "pass": 0,
                        "fail": 0,
                        "manual": 0,
                        "total": total_checks,
                    },
                    "status": req_status_val,
                }

                # Update requirements status counts for the framework
                if req_status_val == "MANUAL":
                    requirements_status["manual"] += 1
                elif req_status_val == "PASS":
                    requirements_status["passed"] += 1

                # Add requirement to compliance requirements
                compliance_requirements[requirement.Id] = requirement_dict

            # Build compliance dictionary
            compliance_dict = {
                "framework": compliance_data.Framework,
                "name": compliance_data.Name,
                "version": compliance_data.Version,
                "provider": provider_type,
                "description": compliance_data.Description,
                "requirements": compliance_requirements,
                "requirements_status": requirements_status,
                "total_requirements": total_requirements,
            }

            # Add compliance to provider compliance
            provider_compliance[compliance_name] = compliance_dict

    return template
