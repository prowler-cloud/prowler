SCANNERS_CHOICES = [
    "vuln",
    "secret",
    "misconfig",
    "license",
]

IMAGE_CONFIG_SCANNERS_CHOICES = [
    "misconfig",
    "secret",
]

SEVERITY_CHOICES = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "UNKNOWN",
]


def init_parser(self):
    """Init the Image Provider CLI parser"""
    image_parser = self.subparsers.add_parser(
        "image", parents=[self.common_providers_parser], help="Container Image Provider"
    )

    # Image Selection
    image_selection_group = image_parser.add_argument_group("Image Selection")
    image_selection_group.add_argument(
        "--image",
        "-I",
        dest="images",
        action="append",
        default=[],
        help="Container image to scan. Can be specified multiple times. Examples: nginx:latest, alpine:3.18, myregistry.io/myapp:v1.0",
    )

    image_selection_group.add_argument(
        "--image-list",
        dest="image_list_file",
        default=None,
        help="Path to a file containing list of images to scan (one per line). Lines starting with # are treated as comments.",
    )

    # Scan Configuration
    scan_config_group = image_parser.add_argument_group("Scan Configuration")
    scan_config_group.add_argument(
        "--scanners",
        "--scanner",
        dest="scanners",
        nargs="+",
        default=["vuln", "secret"],
        choices=SCANNERS_CHOICES,
        help="Trivy scanners to use. Default: vuln, secret. Available: vuln, secret, misconfig, license",
    )

    scan_config_group.add_argument(
        "--image-config-scanners",
        dest="image_config_scanners",
        nargs="+",
        default=[],
        choices=IMAGE_CONFIG_SCANNERS_CHOICES,
        help="Trivy image config scanners (scans Dockerfile-level metadata). Available: misconfig, secret",
    )

    scan_config_group.add_argument(
        "--trivy-severity",
        dest="trivy_severity",
        nargs="+",
        default=[],
        choices=SEVERITY_CHOICES,
        help="Filter Trivy findings by severity. Default: all severities. Available: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN",
    )

    scan_config_group.add_argument(
        "--ignore-unfixed",
        dest="ignore_unfixed",
        action="store_true",
        default=False,
        help="Ignore vulnerabilities without available fixes.",
    )

    scan_config_group.add_argument(
        "--timeout",
        dest="timeout",
        default="5m",
        help="Trivy scan timeout. Default: 5m. Examples: 10m, 1h",
    )


def validate_arguments(arguments):
    """Validate Image provider arguments."""
    images = getattr(arguments, "images", [])
    image_list_file = getattr(arguments, "image_list_file", None)

    if not images and not image_list_file:
        return (
            False,
            "At least one image must be specified using --image (-I) or --image-list.",
        )

    return (True, "")
