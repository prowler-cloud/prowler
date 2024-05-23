from typing import Any

from prowler.lib.check.check import execute
from prowler.lib.check.models import Check_Report
from prowler.lib.logger import logger
from prowler.providers.common.models import Audit_Metadata


def scan(
    checks_to_execute: list,
    global_provider: Any,
    custom_checks_metadata: Any,
) -> list[Check_Report]:
    try:
        # List to store all the check's findings
        all_findings = []
        # Services and checks executed for the Audit Status
        services_executed = set()
        checks_executed = set()

        # Initialize the Audit Metadata
        # TODO: this should be done in the provider class
        # Refactor(Core): Audit manager?
        global_provider.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=checks_to_execute,
            completed_checks=0,
            audit_progress=0,
        )

        for check_name in checks_to_execute:
            try:
                # Recover service from check name
                service = check_name.split("_")[0]

                check_findings = execute(
                    service,
                    check_name,
                    global_provider,
                    services_executed,
                    checks_executed,
                    custom_checks_metadata,
                )
                all_findings.extend(check_findings)

            # If check does not exists in the provider or is from another provider
            except ModuleNotFoundError:
                logger.error(
                    f"Check '{check_name}' was not found for the {global_provider.type.upper()} provider"
                )
            except Exception as error:
                logger.error(
                    f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
    except Exception as error:
        logger.error(
            f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )

    return all_findings
