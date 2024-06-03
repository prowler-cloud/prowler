import typer

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


@app.command()
def main(
    provider: str,
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
    list_compliance_requirements_value: list[str] = typer.Option(
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
