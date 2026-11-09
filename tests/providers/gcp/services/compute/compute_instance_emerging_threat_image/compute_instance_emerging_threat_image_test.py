from unittest import mock

from tests.lib.threats.demo_signature import with_demo
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider

CHECK = "prowler.providers.gcp.services.compute.compute_instance_emerging_threat_image.compute_instance_emerging_threat_image"
DEMOOS_IMAGE_NAME = "demoos-3-20-3-x86-64-bios-tiny-r0"


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
        assert result[0].status_extended.startswith(
            "VM Instance demoos-host boots from image demoos-3-20-3-x86-64-bios-tiny-r0"
        )
        assert "patched in place" in result[0].status_extended
        [threat] = result[0].raw["threats"]
        assert threat["id"] == "demo-ssh-bypass"
        assert threat["provenance"] == "name"
        assert threat["public_route"] is True

    def test_instance_without_a_public_ip_has_no_public_route(self):
        result = _run([_instance(DEMOOS_IMAGE_NAME, GCP_PROJECT_ID, public_ip=False)])
        [threat] = result[0].raw["threats"]
        assert threat["public_route"] is False
        assert threat["exposure_ports"] == [22]

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


DISK_URL = (
    "https://www.googleapis.com/compute/v1/projects/{project}/{scope}/disks/{name}"
)
IMAGE_URL = (
    "https://www.googleapis.com/compute/v1/projects/{project}/global/images/{name}"
)
DEMOOS_IMAGE = "demoos-3-20-3-x86-64-bios-tiny-r0"


class _FakeDisks:
    """``disks()`` or ``regionDisks()``: pages of disks, or a failure."""

    def __init__(self, pages=(), fail_on_page=None):
        self.pages = list(pages)
        self.fail_on_page = fail_on_page
        self.calls = []

    def list(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeRequest(self, 0)

    def list_next(self, previous_request, previous_response):
        index = previous_request.index + 1
        return _FakeRequest(self, index) if index < len(self.pages) else None


class _FakeRequest:
    def __init__(self, disks, index):
        self.disks = disks
        self.index = index

    def execute(self, **_):
        if self.disks.fail_on_page == self.index:
            raise RuntimeError("compute.disks.list denied")
        return {"items": self.disks.pages[self.index]}


def _collector(zonal=None, regional=None):
    """A Compute service whose disk APIs are the given fakes."""
    from prowler.providers.gcp.services.compute.compute_service import Compute

    compute = Compute.__new__(Compute)
    compute.client = mock.MagicMock()
    compute.client.disks.return_value = zonal or _FakeDisks()
    compute.client.regionDisks.return_value = regional or _FakeDisks()
    compute._disk_images_cache = {}
    compute.__get_AuthorizedHttp_client__ = lambda: None
    return compute


def _instance_from(compute, attached_disks):
    """The instance the service would build, run through ``_boot_image``."""
    name, project, failed = compute._boot_image(
        GCP_PROJECT_ID, "us-central1-a", attached_disks
    )
    instance = _instance(name, project)
    instance.boot_image_lookup_failed = failed
    return instance


class Test_compute_boot_image_collection:
    def test_zonal_boot_disk_from_a_later_page_reaches_the_check(self):
        zonal = _FakeDisks(
            pages=[
                [{"name": "data-disk"}],
                [
                    {
                        "name": "boot-disk",
                        "sourceImage": IMAGE_URL.format(
                            project="demo-images", name=DEMOOS_IMAGE
                        ),
                    }
                ],
            ]
        )
        boot = DISK_URL.format(
            project=GCP_PROJECT_ID, scope="zones/us-central1-a", name="boot-disk"
        )
        instance = _instance_from(
            _collector(zonal=zonal), [{"boot": True, "source": boot}]
        )

        assert (instance.boot_image, instance.boot_image_project) == (
            DEMOOS_IMAGE,
            "demo-images",
        )
        assert _run([instance])[0].status == "FAIL"

    def test_regional_boot_disk_is_read_from_the_regional_disk_api(self):
        regional = _FakeDisks(
            pages=[
                [
                    {
                        "name": "ha-boot",
                        "sourceImage": IMAGE_URL.format(
                            project="demo-images", name=DEMOOS_IMAGE
                        ),
                    }
                ]
            ]
        )
        boot = DISK_URL.format(
            project=GCP_PROJECT_ID, scope="regions/us-central1", name="ha-boot"
        )
        instance = _instance_from(
            _collector(regional=regional), [{"boot": True, "source": boot}]
        )

        assert instance.boot_image == DEMOOS_IMAGE
        assert regional.calls == [{"project": GCP_PROJECT_ID, "region": "us-central1"}]

    def test_failed_disk_list_is_manual_not_pass(self):
        zonal = _FakeDisks(
            pages=[[{"name": "data-disk"}], [{"name": "boot-disk"}]], fail_on_page=1
        )
        boot = DISK_URL.format(
            project=GCP_PROJECT_ID, scope="zones/us-central1-a", name="boot-disk"
        )
        compute = _collector(zonal=zonal)
        first = _instance_from(compute, [{"boot": True, "source": boot}])
        # A second instance in the same zone does not read a partial cache.
        second = _instance_from(compute, [{"boot": True, "source": boot}])

        assert first.boot_image_lookup_failed and second.boot_image_lookup_failed
        result = _run([first])
        assert result[0].status == "MANUAL"
        assert "compute.disks.list" in result[0].status_extended
