from typing import Any

from prowler.lib.check.check import execute, update_audit_metadata
from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class Scan:
    # Maybe not needed
    _provider: Provider
    # Refactor(Core): This should replace the Audit_Metadata
    _number_of_checks_to_execute: int = 0
    _number_of_checks_completed: int = 0
    # TODO: these should hold a list of Checks()
    _checks_to_execute: set[str]
    _service_checks_to_execute: dict[str, set[str]]
    _service_checks_completed: dict[str, set[str]]
    _progress: float = 0.0
    _findings: list = []

    def __init__(self, provider, checks_to_execute):
        self._provider = provider

        self._number_of_checks_to_execute = len(checks_to_execute)

        service_checks_to_execute = dict()
        service_checks_completed = dict()

        for check in checks_to_execute:
            # check -> accessanalyzer_enabled
            # service -> accessanalyzer
            service = get_service_name_from_check_name(check)
            if service not in service_checks_to_execute:
                service_checks_to_execute[service] = set()
            service_checks_to_execute[service].add(check)

        self._service_checks_to_execute = service_checks_to_execute
        self._service_checks_completed = service_checks_completed
        self._checks_to_execute = checks_to_execute

    @property
    def checks_to_execute(self) -> set[str]:
        return self._checks_to_execute

    @property
    def service_checks_to_execute(self) -> dict[str, set[str]]:
        return self._service_checks_to_execute

    @property
    def service_checks_completed(self) -> dict[str, set[str]]:
        return self._service_checks_completed

    @property
    def provider(self) -> Provider:
        return self._provider

    @property
    def progress(self) -> float:
        return self._number_of_checks_completed / self._number_of_checks_to_execute

    @property
    def findings(self) -> list:
        return self._findings

    def scan(
        self,
        custom_checks_metadata: Any,
    ) -> list[Check_Report]:
        try:
            checks_to_execute = self.checks_to_execute
            # Initialize the Audit Metadata
            # TODO: this should be done in the provider class
            # Refactor(Core): Audit manager?
            self._provider.audit_metadata = Audit_Metadata(
                services_scanned=0,  # Refactor(Core): This shouldn't be nee
                expected_checks=checks_to_execute,
                completed_checks=0,
                audit_progress=0,
            )

            for check_name in checks_to_execute:
                try:
                    # Recover service from check name
                    service = get_service_name_from_check_name(check_name)

                    # Execute the check
                    check_findings = execute(
                        service,
                        check_name,
                        self._provider,
                        custom_checks_metadata,
                    )
                    # Store findings
                    self._findings.extend(check_findings)

                    # Remove the executed check
                    self._service_checks_to_execute[service].remove(check_name)
                    if len(self._service_checks_to_execute[service]) == 0:
                        self._service_checks_to_execute.pop(service, None)
                    # Add the completed check
                    if service not in self._service_checks_completed:
                        self._service_checks_completed[service] = set()
                    self._service_checks_completed[service].add(check_name)
                    self._number_of_checks_completed += 1

                    # This should be done just once all the service's checks are completed
                    # This metadata needs to get to the services not within the provider
                    # since it is present in the Scan class
                    self._provider.audit_metadata = update_audit_metadata(
                        self._provider.audit_metadata,
                        self.get_completed_services(),
                        self.get_completed_checks(),
                    )

                # If check does not exists in the provider or is from another provider
                except ModuleNotFoundError:
                    logger.error(
                        f"Check '{check_name}' was not found for the {self._provider.type.upper()} provider"
                    )
                except Exception as error:
                    logger.error(
                        f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return self._findings

    def get_completed_services(self):
        return self._service_checks_completed.keys()

    def get_completed_checks(self):
        completed_checks = set()
        for checks in self._service_checks_completed.values():
            completed_checks.update(checks)
        return completed_checks


def get_service_name_from_check_name(check_name: str) -> str:
    """
    get_service_name_from_check_name returns the service name for a given check name.

    Example:
        get_service_name_from_check_name("ec2_instance_public") -> "ec2"
    """
    return check_name.split("_")[0]
