"""End-to-end tests that exercise the real ``load_and_validate_config_file``
through a temp YAML file. Anything that breaks here would break the actual
``prowler aws -c …`` code path."""

import logging
import os
import pathlib

import pytest

from prowler.config.config import load_and_validate_config_file


@pytest.fixture
def write_config(tmp_path):
    def _write(content: str) -> str:
        path = tmp_path / "config.yaml"
        path.write_text(content)
        return str(path)

    return _write


class Test_Loader_With_Schema_Integration:
    def test_shipped_default_config_loads_without_warnings(self, caplog):
        """The default ``prowler/config/config.yaml`` must round-trip every
        provider WITHOUT emitting any schema warnings. If this fails,
        someone added a key to the YAML without updating the schema."""
        repo_root = pathlib.Path(os.path.dirname(os.path.realpath(__file__))).parents[2]
        shipped = repo_root / "prowler" / "config" / "config.yaml"
        with caplog.at_level(logging.WARNING, logger="prowler"):
            for provider in [
                "aws",
                "azure",
                "gcp",
                "kubernetes",
                "m365",
                "github",
                "mongodbatlas",
                "cloudflare",
                "vercel",
            ]:
                cfg = load_and_validate_config_file(provider, str(shipped))
                # Provider always exists in the shipped file → non-empty.
                assert cfg, f"{provider} returned an empty config"

        offending = [
            r.getMessage()
            for r in caplog.records
            if "prowler.config[" in r.getMessage()
        ]
        assert not offending, (
            "Shipped config.yaml triggered schema warnings — schema or YAML out of sync:\n"
            + "\n".join(offending)
        )

    def test_user_config_with_bad_threshold_falls_back(self, write_config, caplog):
        path = write_config(
            "aws:\n"
            "  threat_detection_privilege_escalation_threshold: 5.0\n"
            "  lambda_min_azs: 2\n"
        )
        with caplog.at_level(logging.WARNING, logger="prowler"):
            cfg = load_and_validate_config_file("aws", path)
        assert cfg == {"lambda_min_azs": 2}
        assert any(
            "threat_detection_privilege_escalation_threshold" in r.getMessage()
            for r in caplog.records
        )

    def test_old_format_config_still_works(self, write_config):
        # Old format = flat keys, no provider header.
        path = write_config(
            "max_ec2_instance_age_in_days: 90\n"
            "ecr_repository_vulnerability_minimum_severity: HIGH\n"
        )
        cfg = load_and_validate_config_file("aws", path)
        assert cfg == {
            "max_ec2_instance_age_in_days": 90,
            "ecr_repository_vulnerability_minimum_severity": "HIGH",
        }

    def test_unknown_keys_pass_through_via_loader(self, write_config):
        path = write_config(
            "aws:\n" "  third_party_plugin_setting: hello\n" "  lambda_min_azs: 2\n"
        )
        cfg = load_and_validate_config_file("aws", path)
        assert cfg == {
            "third_party_plugin_setting": "hello",
            "lambda_min_azs": 2,
        }

    def test_quoted_numeric_is_coerced_via_loader(self, write_config):
        # YAML quotes the number: ``"180"`` arrives as a Python str.
        # The schema must coerce it to int so downstream comparisons work.
        path = write_config('aws:\n  max_ec2_instance_age_in_days: "180"\n')
        cfg = load_and_validate_config_file("aws", path)
        assert cfg == {"max_ec2_instance_age_in_days": 180}
        assert isinstance(cfg["max_ec2_instance_age_in_days"], int)

    def test_invalid_yaml_shape_list_as_string_drops_key(self, write_config, caplog):
        path = write_config(
            "aws:\n"
            "  disallowed_regions: me-south-1\n"  # forgot list dashes
            "  lambda_min_azs: 2\n"
        )
        with caplog.at_level(logging.WARNING, logger="prowler"):
            cfg = load_and_validate_config_file("aws", path)
        assert cfg == {"lambda_min_azs": 2}
        assert any("disallowed_regions" in r.getMessage() for r in caplog.records)

    def test_other_providers_unaffected_by_aws_block(self, write_config):
        path = write_config(
            "aws:\n  max_ec2_instance_age_in_days: 90\n" "gcp:\n  mig_min_zones: 5\n"
        )
        assert load_and_validate_config_file("aws", path) == {
            "max_ec2_instance_age_in_days": 90
        }
        assert load_and_validate_config_file("gcp", path) == {"mig_min_zones": 5}

    def test_missing_provider_block_returns_empty(self, write_config):
        path = write_config("aws:\n  max_ec2_instance_age_in_days: 90\n")
        assert load_and_validate_config_file("azure", path) == {}
