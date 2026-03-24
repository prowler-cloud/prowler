"""ASPM Provider CLI argument definitions."""


def init_parser(self):
    """Init the ASPM Provider CLI parser."""
    aspm_parser = self.subparsers.add_parser(
        "aspm",
        parents=[self.common_providers_parser],
        help="Agent Security Posture Management (ASPM) Provider (Beta)",
    )

    aspm_scan_group = aspm_parser.add_argument_group("ASPM Scan Options")

    aspm_scan_group.add_argument(
        "--manifest-path",
        "-M",
        dest="manifest_path",
        default="aspm-manifest.yaml",
        help=(
            "Path to the ASPM agent manifest file (YAML or JSON) describing "
            "deployed AI agent security configurations. "
            "Default: aspm-manifest.yaml"
        ),
    )

    aspm_scan_group.add_argument(
        "--environment",
        dest="environment",
        default=None,
        choices=["prod", "staging", "dev"],
        help=(
            "Filter the assessment to agents in a specific environment. "
            "Default: all environments."
        ),
    )

    aspm_scan_group.add_argument(
        "--cloud-provider",
        dest="cloud_provider",
        default=None,
        choices=["aws", "azure", "gcp"],
        help=(
            "Filter the assessment to agents running on a specific cloud provider. "
            "Default: all cloud providers."
        ),
    )

    aspm_scan_group.add_argument(
        "--provider-uid",
        dest="provider_uid",
        default=None,
        help="Unique identifier for this ASPM scan (used with --push-to-cloud).",
    )


def validate_arguments(arguments):
    """Validate ASPM provider arguments."""
    import os

    manifest_path = getattr(arguments, "manifest_path", "aspm-manifest.yaml")
    if not os.path.exists(manifest_path):
        return (
            False,
            f"ASPM manifest file not found: '{manifest_path}'. "
            "Use --manifest-path to specify the correct path.",
        )
    return (True, "")
