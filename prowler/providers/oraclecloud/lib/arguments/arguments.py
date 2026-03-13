from argparse import ArgumentTypeError, Namespace
from re import match

from prowler.providers.oraclecloud.config import OCI_DEFAULT_CONFIG_FILE, OCI_REGIONS


def init_parser(self):
    """Init the Oracle Cloud Infrastructure Provider CLI parser"""
    oci_parser = self.subparsers.add_parser(
        "oraclecloud",
        parents=[self.common_providers_parser],
        help="Oracle Cloud Infrastructure Provider",
    )

    # Config File Authentication Options
    oci_config_subparser = oci_parser.add_argument_group("Config File Authentication")
    oci_config_subparser.add_argument(
        "--oci-config-file",
        "-cf",
        nargs="?",
        default=None,
        help=f"OCI config file path. Defaults to {OCI_DEFAULT_CONFIG_FILE}",
    )
    oci_config_subparser.add_argument(
        "--profile",
        "-p",
        nargs="?",
        default=None,
        help="OCI profile to use from the config file. Defaults to DEFAULT",
    )

    # Instance Principal Authentication
    oci_instance_principal_subparser = oci_parser.add_argument_group(
        "Instance Principal Authentication"
    )
    oci_instance_principal_subparser.add_argument(
        "--use-instance-principal",
        "--instance-principal",
        action="store_true",
        help="Use OCI Instance Principal authentication (only works when running inside an OCI compute instance)",
    )

    # OCI Regions
    oci_regions_subparser = oci_parser.add_argument_group("OCI Regions")
    oci_regions_subparser.add_argument(
        "--region",
        "-r",
        nargs="?",
        help="OCI region to run Prowler against. If not specified, all subscribed regions will be audited",
        choices=list(OCI_REGIONS.keys()),
    )

    # OCI Compartments
    oci_compartments_subparser = oci_parser.add_argument_group("OCI Compartments")
    oci_compartments_subparser.add_argument(
        "--compartment-id",
        "--compartment",
        nargs="+",
        default=None,
        type=validate_compartment_ocid,
        help="OCI compartment OCIDs to audit. If not specified, all compartments in the tenancy will be audited",
    )


def validate_compartment_ocid(ocid: str) -> str:
    """
    Validates that the input compartment OCID is valid.

    Args:
        ocid (str): The compartment OCID to validate.

    Returns:
        str: The validated compartment OCID.

    Raises:
        ArgumentTypeError: If the compartment OCID is invalid.
    """
    # OCID pattern for compartment: ocid1.compartment.<realm>.<region>.<unique_id>
    # or ocid1.tenancy.<realm>.<region>.<unique_id> for root compartment
    ocid_pattern = (
        r"^ocid1\.(compartment|tenancy)\.[a-z0-9_-]+\.[a-z0-9_-]*\.[a-z0-9]+$"
    )

    if match(ocid_pattern, ocid):
        return ocid
    else:
        raise ArgumentTypeError(
            f"Invalid compartment OCID format: {ocid}. "
            "Expected format: ocid1.compartment.<realm>.<region>.<unique_id>"
        )


def validate_arguments(arguments: Namespace) -> tuple[bool, str]:
    """
    validate_arguments returns {True, ""} if the provider arguments passed are valid
    and can be used together. It performs an extra validation, specific for the OCI provider,
    apart from the argparse lib.

    Args:
        arguments (Namespace): The parsed arguments.

    Returns:
        tuple[bool, str]: A tuple containing a boolean indicating validity and an error message.
    """
    # Check if instance principal and config file/profile are used together
    if arguments.use_instance_principal and (
        arguments.oci_config_file or arguments.profile
    ):
        return (
            False,
            "Cannot use --use-instance-principal with --oci-config-file or --profile options",
        )

    return (True, "")
