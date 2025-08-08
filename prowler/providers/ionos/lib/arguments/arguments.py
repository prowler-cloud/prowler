from argparse import ArgumentTypeError, Namespace
from re import fullmatch, search

def init_parser(self):
    """
    Define and return the argument parser for the IONOS provider.
    """
    ionos_parser = self.subparsers.add_parser(
        "ionos", parents=[self.common_providers_parser], help="IONOS Provider"
    )

    ionos_parser.add_argument(
        "--ionosctl",
        action="store_true",
        required=False,
        help="Use ionosctl token authentication for IONOS Cloud."
    )

    ionos_parser.add_argument(
        "--ionos-user-env-vars",
        action="store_true",
        required=False,
        help="Use IONOS_USERNAME and IONOS_PASSWORD environment variables for authentication."
    )

    ionos_parser.add_argument(
        "--ionos-username",
        required=False,
        help="The username for IONOS Cloud authentication (requires --ionos-password)."
    )
    
    ionos_parser.add_argument(
        "--ionos-password",
        required=False,
        help="The password for IONOS Cloud authentication (requires --ionos-username)."
    )

    ionos_parser.add_argument(
        "--ionos-datacenter-name",
        required=False,
        help="The name of the datacenter to scan. If not provided, the first datacenter will be scanned."
    )
    
    #ionos_parser.add_argument(
    #    "--config-file",
    #    required=False,
    #    default=None,
    #    help="Path to the configuration file for IONOS Cloud auditing."
    #)
    
    #ionos_parser.add_argument(
    #    "--mutelist-file",
    #    required=False,
    #    default=None,
    #    help="Path to the mutelist file to ignore specific checks."
    #)
