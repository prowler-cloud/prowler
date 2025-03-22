from argparse import ArgumentTypeError, Namespace
from re import fullmatch, search

def init_parser(self):
    """
    Define and return the argument parser for the IONOS provider.
    """
    print('Initializing IONOS parser...')
    ionos_parser = self.subparsers.add_parser(
        "ionos", parents=[self.common_providers_parser], help="IONOS Provider"
    )

    ionos_parser.add_argument(
        "--ionos-username",
        required=False,
        help="The username for IONOS Cloud authentication."
    )
    
    ionos_parser.add_argument(
        "--ionos-password",
        required=False,
        help="The password for IONOS Cloud authentication."
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
