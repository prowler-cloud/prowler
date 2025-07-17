def init_parser(self):
    """Initialize the MongoDB Atlas Provider CLI parser"""
    mongodbatlas_parser = self.subparsers.add_parser(
        "mongodbatlas",
        parents=[self.common_providers_parser],
        help="MongoDB Atlas Provider",
    )

    mongodbatlas_auth_subparser = mongodbatlas_parser.add_argument_group(
        "Authentication Modes"
    )

    mongodbatlas_auth_subparser.add_argument(
        "--atlas-public-key",
        nargs="?",
        help="MongoDB Atlas API public key",
        default=None,
        metavar="ATLAS_PUBLIC_KEY",
    )

    mongodbatlas_auth_subparser.add_argument(
        "--atlas-private-key",
        nargs="?",
        help="MongoDB Atlas API private key",
        default=None,
        metavar="ATLAS_PRIVATE_KEY",
    )


def validate_arguments(arguments):
    """Validate MongoDB Atlas provider arguments"""
    # No specific validation needed for MongoDB Atlas arguments currently
    return (True, "")
