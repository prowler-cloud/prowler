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

    # Registry Scan Mode
    registry_group = image_parser.add_argument_group("Registry Scan Mode")
    registry_group.add_argument(
        "--registry",
        dest="registry",
        default=None,
        help="Registry URL to enumerate and scan all images. Examples: myregistry.io, docker.io/myorg, 123456789.dkr.ecr.us-east-1.amazonaws.com",
    )
    registry_group.add_argument(
        "--image-filter",
        dest="image_filter",
        default=None,
        help="Regex to filter repository names during registry enumeration (re.search). Example: '^prod/.*'",
    )
    registry_group.add_argument(
        "--tag-filter",
        dest="tag_filter",
        default=None,
        help=r"Regex to filter tags during registry enumeration (re.search). Example: '^(latest|v\d+\.\d+\.\d+)$'",
    )
    registry_group.add_argument(
        "--max-images",
        dest="max_images",
        type=int,
        default=0,
        help="Maximum number of images to scan from registry. 0 = unlimited. Aborts if exceeded.",
    )
    registry_group.add_argument(
        "--registry-insecure",
        dest="registry_insecure",
        action="store_true",
        default=False,
        help="Skip TLS verification for registry connections (for self-signed certificates).",
    )
    registry_group.add_argument(
        "--registry-list",
        dest="registry_list_images",
        action="store_true",
        default=False,
        help="List all repositories and tags from the registry, then exit without scanning. Useful for discovering available images before building --image-filter or --tag-filter.",
    )


def validate_arguments(arguments):
    """Validate Image provider arguments."""
    images = getattr(arguments, "images", [])
    image_list_file = getattr(arguments, "image_list_file", None)
    registry = getattr(arguments, "registry", None)
    image_filter = getattr(arguments, "image_filter", None)
    tag_filter = getattr(arguments, "tag_filter", None)
    max_images = getattr(arguments, "max_images", 0)
    registry_insecure = getattr(arguments, "registry_insecure", False)
    registry_list_images = getattr(arguments, "registry_list_images", False)

    if registry_list_images and not registry:
        return (False, "--registry-list requires --registry.")

    if not images and not image_list_file and not registry:
        return (
            False,
            "At least one image source must be specified using --image (-I), --image-list, or --registry.",
        )

    # Registry-only flags require --registry
    if not registry:
        if image_filter:
            return (False, "--image-filter requires --registry.")
        if tag_filter:
            return (False, "--tag-filter requires --registry.")
        if max_images:
            return (False, "--max-images requires --registry.")
        if registry_insecure:
            return (False, "--registry-insecure requires --registry.")

    # Docker Hub namespace validation
    if registry:
        url = registry.rstrip("/")
        for prefix in ("https://", "http://"):
            if url.startswith(prefix):
                url = url[len(prefix) :]
                break
        stripped = url
        for prefix in ("registry-1.docker.io", "docker.io"):
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix) :].lstrip("/")
                if not stripped:
                    return (
                        False,
                        "Docker Hub requires a namespace. Use --registry docker.io/{org_or_user}.",
                    )
                break

    return (True, "")
