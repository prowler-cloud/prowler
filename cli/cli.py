import typer

from prowler.config.config import available_compliance_frameworks
from prowler.lib.banner import print_banner
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
aws = typer.Typer(name="aws")
azure = typer.Typer(name="azure")
gcp = typer.Typer(name="gcp")
kubernetes = typer.Typer(name="kubernetes")

app.add_typer(aws, name="aws")
app.add_typer(azure, name="azure")
app.add_typer(gcp, name="gcp")
app.add_typer(kubernetes, name="kubernetes")


def list_resources(provider: str, resource_type: str):
    print_banner(False)
    if resource_type == "services":
        print_services(list_services(provider))
    elif resource_type == "fixers":
        print_fixers(list_fixers(provider))
    elif resource_type == "categories":
        print_categories(list_categories(bulk_load_checks_metadata(provider)))
    elif resource_type == "compliance":
        print_compliance_frameworks(bulk_load_compliance_frameworks(provider))
    elif resource_type in ["checks", "checks-json"]:
        bulk_checks_metadata = bulk_load_checks_metadata(provider)
        # TODO fill the rest of the arguments
        checks_to_execute = load_checks_to_execute(
            bulk_checks_metadata,
            bulk_load_compliance_frameworks(provider),
            None,
            [],
            [],
            [],
            [],
            [],
            provider,
        )
        if resource_type == "checks":
            print_checks(provider, sorted(checks_to_execute), bulk_checks_metadata)
        elif resource_type == "checks-json":
            print(list_checks_json(provider, sorted(checks_to_execute)))


def list_compliance_requirements(
    provider: str, compliance_frameworks: list[str] = None
):
    print_banner(False)
    print_compliance_requirements(
        bulk_load_compliance_frameworks(provider), compliance_frameworks
    )


def validate_frameworks(compliance_frameworks: list[str] = None):
    if not compliance_frameworks:
        raise typer.BadParameter("Expected at least one argument")
    for framework in compliance_frameworks:
        if framework not in available_compliance_frameworks:
            print(f"{framework} is not a valid Compliance Framework\n")
    return compliance_frameworks


def create_list_commands(provider_typer: typer.Typer):
    provider_name = provider_typer.info.name

    @provider_typer.command(
        "list-services",
        help=f"List the {provider_name} services that are supported by Prowler.",
    )
    def list_services_command():
        list_resources(provider_name, "services")

    @provider_typer.command(
        "list-fixers",
        help=f"List the {provider_name} fixers that are supported by Prowler.",
    )
    def list_fixers_command():
        list_resources(provider_name, "fixers")

    @provider_typer.command(
        "list-categories",
        help=f"List the {provider_name} categories that are supported by Prowler.",
    )
    def list_categories_command():
        list_resources(provider_name, "categories")

    @provider_typer.command(
        "list-compliance",
        help=f"List the {provider_name} compliance frameworks that are supported by Prowler.",
    )
    def list_compliance_command():
        list_resources(provider_name, "compliance")

    # The compliance requirements should be inside available_compliance_frameworks
    @provider_typer.command(
        "list-compliance-requirements",
        help=f"List the {provider_name} compliance frameworks requirements that are supported by Prowler.",
    )
    def list_compliance_requirements_command(
        list_compliance_frameworks: list[str] = typer.Argument(
            help="List requirements and checks per compliance framework",
            callback=validate_frameworks,
            default=None,
        ),
    ):
        list_compliance_requirements(provider_name, list_compliance_frameworks)

    @provider_typer.command(
        "list-checks",
        help=f"List the {provider_name} checks that are supported by Prowler.",
    )
    def list_checks_command():
        list_resources(provider_name, "checks")

    @provider_typer.command(
        "list-checks-json",
        help=f"List the {provider_name} checks that are supported by Prowler in JSON format.",
    )
    def list_checks_json_command():
        list_resources(provider_name, "checks-json")


create_list_commands(aws)
create_list_commands(azure)
create_list_commands(gcp)
create_list_commands(kubernetes)


if __name__ == "__main__":
    app()
