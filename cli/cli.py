import typer

from prowler.lib.banner import print_banner
from prowler.lib.check.check import list_services, print_services

app = typer.Typer()
aws = typer.Typer()
azure = typer.Typer()
gcp = typer.Typer()
kubernetes = typer.Typer()
app.add_typer(aws, name="aws")
app.add_typer(azure, name="azure")
app.add_typer(gcp, name="gcp")
app.add_typer(kubernetes, name="kubernetes")


@aws.command(
    "list-services", help="List the AWS services that are supported by Prowler."
)
def list_services_aws():
    print_services(list_services("aws"))


@azure.command(
    "list-services", help="List the Azure services that are supported by Prowler."
)
def list_services_azure():
    print_services(list_services("azure"))


@gcp.command(
    "list-services", help="List the GCP services that are supported by Prowler."
)
def list_services_gcp():
    print_services(list_services("gcp"))


@kubernetes.command(
    "list-services", help="List the Kubernetes services that are supported by Prowler."
)
def list_services_kubernetes():
    print_services(list_services("kubernetes"))


@app.command("banner", help="Prints the banner of the tool.")
def banner(show: bool = True):
    if show:
        print_banner(show)
    else:
        print("Banner is not shown.")


if __name__ == "__main__":
    app()
