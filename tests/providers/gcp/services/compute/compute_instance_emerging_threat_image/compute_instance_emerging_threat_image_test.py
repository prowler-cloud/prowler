from unittest import mock

from tests.lib.threats.demo_signature import with_demo
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

CHECK = "prowler.providers.gcp.services.compute.compute_instance_emerging_threat_image.compute_instance_emerging_threat_image"


def _instance(boot_image="", boot_image_project="", public_ip=True):
    from prowler.providers.gcp.services.compute.compute_service import Instance

    return Instance(
        name="demoos-host",
        id="1234567890",
        zone="us-central1-a",
        region="us-central1",
        public_ip=public_ip,
        metadata={},
        shielded_enabled_vtpm=True,
        shielded_enabled_integrity_monitoring=True,
        confidential_computing=False,
        service_accounts=[],
        ip_forward=False,
        disks_encryption=[],
        project_id=GCP_PROJECT_ID,
        boot_image=boot_image,
        boot_image_project=boot_image_project,
    )


def _run(instances, audit_config=None):
    compute_client = mock.MagicMock()
    compute_client.project_ids = [GCP_PROJECT_ID]
    compute_client.instances = instances
    compute_client.audit_config = with_demo(audit_config)
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ),
        mock.patch(f"{CHECK}.compute_client", new=compute_client),
    ):
        from prowler.providers.gcp.services.compute.compute_instance_emerging_threat_image.compute_instance_emerging_threat_image import (
            compute_instance_emerging_threat_image,
        )

        return compute_instance_emerging_threat_image().execute()


class Test_compute_instance_emerging_threat_image:
    def test_no_instances(self):
        assert _run([]) == []

    def test_imported_demoos_tiny_fails(self):
        result = _run([_instance("demoos-3-20-3-x86-64-bios-tiny-r0", GCP_PROJECT_ID)])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].project_id == GCP_PROJECT_ID
        assert result[0].location == "us-central1-a"
        [threat] = result[0].raw["threats"]
        assert threat["id"] == "demo-ssh-bypass"
        assert threat["provenance"] == "name"
        assert threat["public_route"] is True

    def test_debian_image_passes(self):
        result = _run([_instance("debian-12-bookworm-v20261010", "debian-cloud")])
        assert result[0].status == "PASS"
        assert result[0].raw == {}

    def test_unknown_boot_image_passes_with_reason(self):
        result = _run([_instance()])
        assert result[0].status == "PASS"
        assert "does not report the image" in result[0].status_extended

    def test_image_project_verifies_scan_configuration_signature(self):
        signature = {
            "id": "demo-debian-flaw",
            "title": "Demo Debian image flaw",
            "cves": ["CVE-2026-0003"],
            "severity": "high",
            "summary": "Demo.",
            "images": [
                {
                    "cloud": "gcp",
                    "publishers": ["debian-cloud"],
                    "require_publisher": True,
                    "name_regex": r"^debian-12-bookworm-v2026",
                }
            ],
            "credential_required": True,
            "impact": "Local privilege escalation.",
            "remediation": "Upgrade.",
        }
        official = _run(
            [_instance("debian-12-bookworm-v20261010", "debian-cloud")],
            audit_config={"threat_signatures": [signature]},
        )
        lookalike = _run(
            [_instance("debian-12-bookworm-v20261010", GCP_PROJECT_ID)],
            audit_config={"threat_signatures": [signature]},
        )
        assert official[0].status == "FAIL"
        assert official[0].check_metadata.Severity.value == "high"
        assert official[0].raw["threats"][0]["provenance"] == "publisher"
        assert lookalike[0].status == "PASS"
