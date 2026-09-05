from prowler.lib.check.models import CheckMetadata

EXPECTED_CHECKS = {
    "app_no_public_ip_address": {
        "service": "app",
        "severity": "high",
        "resource_type": "FlyApp",
        "categories": ["internet-exposed"],
    },
    "app_uses_dedicated_private_network": {
        "service": "app",
        "severity": "medium",
        "resource_type": "FlyApp",
        "categories": ["trust-boundaries"],
    },
    "machine_image_pinned_to_digest": {
        "service": "machine",
        "severity": "medium",
        "resource_type": "FlyMachine",
        "categories": ["software-supply-chain"],
    },
    "machine_no_plaintext_secrets_in_env": {
        "service": "machine",
        "severity": "high",
        "resource_type": "FlyMachine",
        "categories": ["secrets"],
    },
    "machine_no_public_non_http_ports": {
        "service": "machine",
        "severity": "high",
        "resource_type": "FlyMachine",
        "categories": ["internet-exposed"],
    },
    "volume_encrypted_at_rest": {
        "service": "volume",
        "severity": "high",
        "resource_type": "FlyVolume",
        "categories": ["encryption"],
    },
}


class TestFlyMetadata:
    def test_fly_checks_are_discovered(self):
        fly_metadata = CheckMetadata.get_bulk(provider="fly")

        assert set(fly_metadata) == set(EXPECTED_CHECKS)

    def test_fly_checks_metadata_is_consistent(self):
        fly_metadata = CheckMetadata.get_bulk(provider="fly")

        for check_id, expected in EXPECTED_CHECKS.items():
            metadata = fly_metadata[check_id]
            assert metadata.Provider == "fly"
            assert metadata.CheckID == check_id
            assert metadata.ServiceName == expected["service"]
            assert metadata.Severity == expected["severity"]
            assert metadata.ResourceType == expected["resource_type"]
            assert metadata.Categories == expected["categories"]
            assert metadata.CheckTitle.startswith("Fly.io ")
            assert metadata.Description
            assert metadata.Risk
            assert metadata.Remediation.Recommendation.Text
            assert (
                metadata.Remediation.Recommendation.Url
                == f"https://hub.prowler.com/check/{check_id}"
            )
            assert metadata.AdditionalURLs
            assert all(url.startswith("https://") for url in metadata.AdditionalURLs)

    def test_fly_checks_have_a_cli_remediation(self):
        fly_metadata = CheckMetadata.get_bulk(provider="fly")

        for metadata in fly_metadata.values():
            assert metadata.Remediation.Code.CLI.startswith("fly ")
            assert metadata.Remediation.Code.Other
