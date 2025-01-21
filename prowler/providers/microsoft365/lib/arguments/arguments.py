from argparse import ArgumentTypeError


def init_parser(self):
    """Init the Microsoft365 Provider CLI parser"""
    microsoft365_parser = self.subparsers.add_parser(
        "microsoft365",
        parents=[self.common_providers_parser],
        help="Microsoft365 Provider",
    )
    # Regions
    microsoft365_regions_subparser = microsoft365_parser.add_argument_group("Regions")
    microsoft365_regions_subparser.add_argument(
        "--region",
        nargs="?",
        default="Microsoft365Global",
        type=validate_microsoft365_region,
        help="microsoft365 region from `az cloud list --output table`, by default Microsoft365Global",
    )


def validate_microsoft365_region(region):
    """validate_microsoft365_region validates if the region passed as argument is valid"""
    regions_allowed = [
        "Microsoft365GlobalChina",
        "Microsoft365USGovernment",
        "Microsoft365Global",
    ]
    if region not in regions_allowed:
        raise ArgumentTypeError(
            f"Region {region} not allowed, allowed regions are {' '.join(regions_allowed)}"
        )
    return region
