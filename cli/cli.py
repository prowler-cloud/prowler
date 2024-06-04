import typer

from prowler.config.config import available_compliance_frameworks
from prowler.lib.check.check import (
    bulk_load_checks_metadata,
    bulk_load_compliance_frameworks,
    list_categories,
    list_checks_json,
    list_fixers,
    list_services,
    print_categories,
    print_checks,
    print_compliance_frameworks,
    print_compliance_requirements,
    print_fixers,
    print_services,
)
from prowler.lib.check.checks_loader import load_checks_to_execute

app = typer.Typer()


def check_provider(provider: str):
    if provider not in ["aws", "azure", "gcp", "kubernetes"]:
        raise typer.BadParameter(
            "Invalid provider. Choose between aws, azure, gcp or kubernetes."
        )


def check_compliance_framework(provider: str, compliance_framework: list):
    # From the available_compliance_frameworks, check if the compliance_framework is valid for the provider
    compliance_frameworks_provider = []
    for provider_compliance_framework in available_compliance_frameworks:
        if provider in provider_compliance_framework:
            compliance_frameworks_provider.append(provider_compliance_framework)
    for compliance in compliance_framework:
        if compliance not in compliance_frameworks_provider:
            raise typer.BadParameter(
                f"{compliance} is not a valid Compliance Framework for {provider}"
            )


@app.command()
def main(
    provider: str = typer.Argument(..., help="The provider to check"),
    list_services_bool: bool = typer.Option(
        False, "--list-services", help="List the services of the provider"
    ),
    list_fixers_bool: bool = typer.Option(
        False, "--list-fixers", help="List the fixers of the provider"
    ),
    list_categories_bool: bool = typer.Option(
        False, "--list-categories", help="List the categories of the provider"
    ),
    list_compliance_bool: bool = typer.Option(
        False,
        "--list-compliance",
        help="List the compliance frameworks of the provider",
    ),
    list_compliance_requirements_value: str = typer.Option(
        None,
        "--list-compliance-requirements",
        help="List the compliance requirements of the provider",
    ),
    list_checks_bool: bool = typer.Option(
        False, "--list-checks", help="List the checks of the provider"
    ),
    list_checks_json_bool: bool = typer.Option(
        False,
        "--list-checks-json",
        help="List the checks of the provider in JSON format",
    ),
):
    check_provider(provider)
    if list_services_bool:
        services = list_services(provider)
        print_services(services)
    if list_fixers_bool:
        fixers = list_fixers(provider)
        print_fixers(fixers)
    if list_categories_bool:
        checks_metadata = bulk_load_checks_metadata(provider)
        categories = list_categories(checks_metadata)
        print_categories(categories)
    if list_compliance_bool:
        compliance_frameworks = bulk_load_compliance_frameworks(provider)
        print_compliance_frameworks(compliance_frameworks)
    if list_compliance_requirements_value:
        list_compliance_requirements_value = list_compliance_requirements_value.split(
            ","
        )
        check_compliance_framework(provider, list_compliance_requirements_value)
        print_compliance_requirements(
            bulk_load_compliance_frameworks(provider),
            list_compliance_requirements_value,
        )
    if list_checks_bool:
        checks_metadata = bulk_load_checks_metadata(provider)
        checks = load_checks_to_execute(
            checks_metadata,
            bulk_load_compliance_frameworks(provider),
            None,
            [],
            [],
            [],
            [],
            [],
            provider,
        )
        print_checks(provider, sorted(checks), checks_metadata)
    if list_checks_json_bool:
        checks_metadata = bulk_load_checks_metadata(provider)
        checks_to_execute = load_checks_to_execute(
            checks_metadata,
            bulk_load_compliance_frameworks(provider),
            None,
            [],
            [],
            [],
            [],
            [],
            provider,
        )
        print(list_checks_json(provider, sorted(checks_to_execute)))


if __name__ == "__main__":
    app()
