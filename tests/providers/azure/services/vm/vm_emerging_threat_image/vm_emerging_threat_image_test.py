from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import (
    LinuxConfiguration,
    VirtualMachine,
    VirtualMachineImage,
)
from tests.lib.threats.demo_signature import with_demo
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)

CHECK = "prowler.providers.azure.services.vm.vm_emerging_threat_image.vm_emerging_threat_image"

GALLERY_DEMOOS_TINY = (
    f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg/providers/"
    "Microsoft.Compute/galleries/images/images/demoos-3.21.2-x86_64-uefi-tiny/versions/1.0.0"
)


def _vm(image=None, password_disabled=None) -> VirtualMachine:
    vm_id = str(uuid4())
    return VirtualMachine(
        resource_id=vm_id,
        resource_name="demoos-host",
        location="westeurope",
        security_profile=None,
        extensions=[],
        image=image,
        linux_configuration=(
            LinuxConfiguration(disable_password_authentication=password_disabled)
            if password_disabled is not None
            else None
        ),
    )


def _run(vms: dict, audit_config=None):
    vm_client = mock.MagicMock()
    vm_client.subscriptions = {AZURE_SUBSCRIPTION_ID: AZURE_SUBSCRIPTION_NAME}
    vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: vms}
    vm_client.audit_config = with_demo(audit_config)
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ),
        mock.patch(f"{CHECK}.vm_client", new=vm_client),
    ):
        from prowler.providers.azure.services.vm.vm_emerging_threat_image.vm_emerging_threat_image import (
            vm_emerging_threat_image,
        )

        return vm_emerging_threat_image().execute()


class Test_vm_emerging_threat_image:
    def test_no_vms(self):
        assert _run({}) == []

    def test_gallery_demoos_tiny_fails(self):
        vm = _vm(VirtualMachineImage(id=GALLERY_DEMOOS_TINY), password_disabled=False)
        result = _run({vm.resource_id: vm})

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].subscription == AZURE_SUBSCRIPTION_ID
        assert result[0].check_metadata.Severity.value == "critical"
        assert result[0].status_extended.startswith(
            f"VM demoos-host in subscription {AZURE_SUBSCRIPTION_NAME}"
        )
        assert "patched in place" in result[0].status_extended
        [threat] = result[0].raw["threats"]
        assert threat["id"] == "demo-ssh-bypass"
        assert threat["provenance"] == "name"
        assert threat["image"] == "demoos-3.21.2-x86_64-uefi-tiny"
        assert threat["mitigations_observed"] == []

    def test_image_reference_collected_by_the_service_reaches_the_check(self):
        from types import SimpleNamespace

        from prowler.providers.azure.services.vm.vm_service import VirtualMachines

        # Shaped like azure.mgmt.compute's ImageReference for a gallery image.
        reference = SimpleNamespace(
            id=GALLERY_DEMOOS_TINY,
            publisher=None,
            offer=None,
            sku=None,
            version=None,
            exact_version=None,
            shared_gallery_image_id=None,
            community_gallery_image_id=None,
        )
        image = VirtualMachines._get_image_details(reference)
        vm = _vm(image)

        result = _run({vm.resource_id: vm})

        assert "demoos-3.21.2-x86_64-uefi-tiny" in image.names
        assert result[0].status == "FAIL"

    def test_password_authentication_disabled_is_recorded(self):
        vm = _vm(VirtualMachineImage(id=GALLERY_DEMOOS_TINY), password_disabled=True)
        result = _run({vm.resource_id: vm})

        assert result[0].status == "FAIL"
        assert result[0].raw["threats"][0]["mitigations_observed"] == [
            "password_authentication_disabled"
        ]

    def test_marketplace_image_passes(self):
        vm = _vm(
            VirtualMachineImage(
                publisher="Canonical",
                offer="ubuntu-24_04-lts",
                sku="server",
                version="latest",
            )
        )
        result = _run({vm.resource_id: vm})
        assert result[0].status == "PASS"

    def test_unknown_image_passes_with_reason(self):
        vm = _vm(None)
        result = _run({vm.resource_id: vm})
        assert result[0].status == "PASS"
        assert "does not report the image" in result[0].status_extended

    def test_marketplace_publisher_verifies_scan_configuration_signature(self):
        signature = {
            "id": "demo-marketplace",
            "title": "Demo marketplace image flaw",
            "severity": "medium",
            "summary": "Demo.",
            "images": [
                {
                    "cloud": "azure",
                    "publishers": ["demo-publisher"],
                    "name_regex": r"^demo-offer-demo-sku",
                }
            ],
            "credential_required": True,
            "impact": "Local privilege escalation.",
            "remediation": "Upgrade.",
        }
        vm = _vm(
            VirtualMachineImage(
                publisher="demo-publisher", offer="demo-offer", sku="demo-sku"
            )
        )
        result = _run(
            {vm.resource_id: vm}, audit_config={"threat_signatures": [signature]}
        )
        assert result[0].status == "FAIL"
        assert result[0].check_metadata.Severity.value == "medium"
        assert result[0].raw["threats"][0]["provenance"] == "publisher"

    def test_resource_group_name_is_not_matched_as_the_image_name(self):
        # The image is "myimg"; only its resource group looks like DemoOS.
        custom = (
            f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/"
            "demoos-3.21.2-x86_64-uefi-tiny-lab/providers/Microsoft.Compute/images/myimg"
        )
        vm = _vm(VirtualMachineImage(id=custom))

        result = _run({vm.resource_id: vm})

        assert result[0].status == "PASS"

    def test_publisher_is_compared_without_case(self):
        signature = {
            "id": "demo-marketplace-flaw",
            "title": "Demo marketplace image flaw",
            "cves": ["CVE-2026-0004"],
            "severity": "high",
            "summary": "Demo.",
            "images": [
                {
                    "cloud": "azure",
                    "publishers": ["Canonical"],
                    "require_publisher": True,
                    "name_regex": r"^ubuntu-24_04-lts",
                }
            ],
            "credential_required": True,
            "impact": "Local privilege escalation.",
            "remediation": "Upgrade.",
        }
        image = VirtualMachineImage(
            publisher="canonical", offer="ubuntu-24_04-lts", sku="server"
        )
        vm = _vm(image)

        result = _run(
            {vm.resource_id: vm}, audit_config={"threat_signatures": [signature]}
        )

        assert result[0].status == "FAIL"
        assert result[0].raw["threats"][0]["provenance"] == "publisher"
