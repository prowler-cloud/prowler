import pytest
import yaml
from pydantic import ValidationError

from prowler.lib.threats import (
    ThreatSignature,
    builtin_signatures,
    describe_matches,
    load_signatures,
    match_image,
    to_match,
)
from prowler.lib.threats.catalog import BUILTIN_DIR
from tests.lib.threats.demo_signature import DEMO_PUBLISHER, DEMO_SSH_BYPASS

DEMO = [ThreatSignature.model_validate(DEMO_SSH_BYPASS)]


def signature(**overrides) -> dict:
    base = {
        "id": "demo-threat",
        "title": "Demo threat",
        "cves": ["CVE-2026-0001"],
        "severity": "high",
        "summary": "A demo.",
        "images": [
            {
                "cloud": "aws",
                "publishers": ["111122223333"],
                "name_regex": r"^demo-(?P<version>\d+\.\d+)$",
                "version_min": "1.2",
                "version_max": "1.4",
            }
        ],
        "credential_required": True,
        "impact": "A shell.",
        "remediation": "Upgrade.",
    }
    base.update(overrides)
    return base


class TestMatching:
    """Matching a signature shaped like a real emerging threat (see demo_signature)."""

    @pytest.mark.parametrize(
        "name,publisher,expected",
        [
            ("demoos-3.22.2-x86_64-uefi-tiny-r0", DEMO_PUBLISHER, "publisher"),
            ("demoos-3.18.11-aarch64-bios-tiny-r0", DEMO_PUBLISHER, "publisher"),
            ("demoos-3.24.3-x86_64-uefi-tiny-r2", DEMO_PUBLISHER, "publisher"),
            ("demoos-3.20.3-x86_64-uefi-tiny-r0", "999999999999", "name"),
            # cloud-init images write PasswordAuthentication no
            ("demoos-3.22.2-x86_64-uefi-cloudinit-r0", DEMO_PUBLISHER, None),
            # outside the affected range
            ("demoos-3.18.10-x86_64-uefi-tiny-r0", DEMO_PUBLISHER, None),
            ("demoos-3.24.4-x86_64-uefi-tiny-r0", DEMO_PUBLISHER, None),
            ("ubuntu-24.04-amd64-server", "099720109477", None),
        ],
    )
    def test_demo_aws_matching(self, name, publisher, expected):
        hits = match_image(DEMO, "aws", [name], publisher)
        if expected is None:
            assert hits == []
        else:
            assert [(h[0].id, h[2]) for h in hits] == [("demo-ssh-bypass", expected)]

    def test_demo_gcp_dashed_versions(self):
        hits = match_image(DEMO, "gcp", ["demoos-3-20-3-x86-64-bios-tiny-r0"], "proj")
        assert [h[0].id for h in hits] == ["demo-ssh-bypass"]

    def test_demo_azure_gallery_definition(self):
        hits = match_image(DEMO, "azure", ["demoos-3.21.2-x86_64-uefi-tiny"], None)
        assert [(h[0].id, h[2]) for h in hits] == [("demo-ssh-bypass", "name")]

    @pytest.mark.parametrize(
        "name",
        [
            # A gallery image definition: Azure resource names ignore case.
            "DemoOS-3.21.2-x86_64-UEFI-Tiny",
            # Marketplace offer-sku-version, in the case the VM was created with.
            "DEMOOS-3.21.2-X86_64-UEFI-TINY",
        ],
    )
    def test_azure_names_are_matched_in_any_case(self, name):
        hits = match_image(DEMO, "azure", [name], None)
        assert [(h[0].id, h[1]) for h in hits] == [("demo-ssh-bypass", name)]

    @pytest.mark.parametrize(
        "cloud,name",
        [
            # AMI and GCP image names are case-sensitive: another case is
            # another image, possibly anybody's.
            ("aws", "DemoOS-3.22.2-x86_64-uefi-tiny-r0"),
            ("gcp", "DemoOS-3-20-3-x86-64-bios-tiny-r0"),
        ],
    )
    def test_aws_and_gcp_names_are_matched_in_their_exact_case(self, cloud, name):
        assert match_image(DEMO, cloud, [name], DEMO_PUBLISHER) == []
        assert match_image(DEMO, cloud, [name.lower()], DEMO_PUBLISHER)


class TestSchema:
    def test_valid(self):
        assert ThreatSignature.model_validate(signature()).id == "demo-threat"

    @pytest.mark.parametrize(
        "overrides",
        [
            {"id": "Has Spaces"},
            {"id": "x" * 41},
            {"cves": ["not-a-cve"]},
            {"severity": "urgent"},
            {"images": []},
            {"unexpected": True},
        ],
    )
    def test_invalid(self, overrides):
        with pytest.raises(ValidationError):
            ThreatSignature.model_validate(signature(**overrides))

    def test_version_bounds_need_a_version_group(self):
        rule = signature()["images"][0] | {"name_regex": "^demo-.*$"}
        with pytest.raises(ValidationError, match="version"):
            ThreatSignature.model_validate(signature(images=[rule]))

    def test_regex_must_compile(self):
        rule = signature()["images"][0] | {"name_regex": "("}
        with pytest.raises(ValidationError, match="compile"):
            ThreatSignature.model_validate(signature(images=[rule]))

    def test_require_publisher_needs_publishers(self):
        rule = {"cloud": "aws", "name_regex": "^x$", "require_publisher": True}
        with pytest.raises(ValidationError, match="publisher"):
            ThreatSignature.model_validate(signature(images=[rule]))


class TestLoadAndMatch:
    def test_supplied_signature_is_added(self):
        loaded = load_signatures({"threat_signatures": [signature()]})
        assert "demo-threat" in {s.id for s in loaded}

    def test_supplied_signature_replaces_builtin_with_same_id(
        self, tmp_path, monkeypatch
    ):
        from prowler.lib.threats import catalog

        (tmp_path / "demo-threat.yaml").write_text(yaml.safe_dump(signature()))
        monkeypatch.setattr(catalog, "BUILTIN_DIR", tmp_path)
        catalog.builtin_signatures.cache_clear()
        try:
            loaded = load_signatures(
                {"threat_signatures": [signature(title="Override")]}
            )
            assert [s.title for s in loaded if s.id == "demo-threat"] == ["Override"]
        finally:
            monkeypatch.undo()
            catalog.builtin_signatures.cache_clear()

    def test_invalid_supplied_signature_is_skipped(self):
        loaded = load_signatures({"threat_signatures": [{"id": "broken"}]})
        assert "broken" not in {s.id for s in loaded}

    def test_non_list_is_ignored(self):
        loaded = load_signatures({"threat_signatures": "nope"})
        assert {s.id for s in loaded} == {s.id for s in builtin_signatures()}

    def test_version_range_is_inclusive(self):
        demo = [ThreatSignature.model_validate(signature())]
        assert match_image(demo, "aws", ["demo-1.2"], "111122223333")
        assert match_image(demo, "aws", ["demo-1.4"], "111122223333")
        assert not match_image(demo, "aws", ["demo-1.5"], "111122223333")
        assert not match_image(demo, "azure", ["demo-1.3"], None)

    def test_require_publisher_rejects_name_only_matches(self):
        rule = signature()["images"][0] | {"require_publisher": True}
        demo = [ThreatSignature.model_validate(signature(images=[rule]))]
        assert not match_image(demo, "aws", ["demo-1.3"], "000000000000")
        assert match_image(demo, "aws", ["demo-1.3"], "111122223333")

    def test_publisher_matches_sort_first(self):
        weak = signature(id="weak-one", severity="critical")
        weak["images"][0]["publishers"] = []
        strong = signature(id="strong-one", severity="low")
        demo = [ThreatSignature.model_validate(s) for s in (weak, strong)]
        hits = match_image(demo, "aws", ["demo-1.3"], "111122223333")
        assert [h[0].id for h in hits] == ["strong-one", "weak-one"]

    def test_publisher_rule_wins_over_an_earlier_name_only_rule(self):
        name_only = signature()["images"][0] | {"publishers": []}
        verified = signature()["images"][0]
        demo = [ThreatSignature.model_validate(signature(images=[name_only, verified]))]
        hits = match_image(demo, "aws", ["demo-1.3"], "111122223333")
        assert [(h[0].id, h[2]) for h in hits] == [("demo-threat", "publisher")]

    def test_match_payload_and_description(self):
        demo = ThreatSignature.model_validate(
            signature(exposure={"protocol": "tcp", "port": 22})
        )
        match = to_match(demo, "demo-1.3", "publisher", exposed_to_internet=True)
        assert match.exposure_port == 22
        assert match.model_dump(mode="json")["cves"] == ["CVE-2026-0001"]
        text = describe_matches([match])
        assert "CVE-2026-0001" in text and "TCP 22 open to the internet" in text


class TestEveryBuiltinSignature:
    """The bar a new signature file clears before it reaches every scanned account."""

    @pytest.mark.parametrize(
        "path", sorted(BUILTIN_DIR.glob("*.yaml")), ids=lambda p: p.name
    )
    def test_signature_file(self, path):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        signature = ThreatSignature.model_validate(raw)
        # The file name is the id, so two files can never claim one threat.
        assert signature.id == path.stem
        assert signature.references, "cite the advisory"
        assert signature.published, "say when it was published"
        for rule in signature.images:
            # Examples are what prove the regex and the version ranges.
            assert (
                rule.examples and rule.examples.matches and rule.examples.misses
            ), f"the {rule.cloud} rule needs examples it matches and misses"

    def test_every_file_loads(self):
        assert len(builtin_signatures()) == len(list(BUILTIN_DIR.glob("*.yaml")))

    def test_template_is_a_valid_signature_but_not_loaded(self):
        template = BUILTIN_DIR / "TEMPLATE.yaml.example"
        ThreatSignature.model_validate(yaml.safe_load(template.read_text()))
        assert "example-threat" not in {s.id for s in builtin_signatures()}

    def test_file_named_after_another_id_is_skipped(self, tmp_path, monkeypatch):
        from prowler.lib.threats import catalog

        # A valid signature, so the file name is the only reason to skip it.
        ThreatSignature.model_validate(signature())
        (tmp_path / "other-name.yaml").write_text(yaml.safe_dump(signature()))
        monkeypatch.setattr(catalog, "BUILTIN_DIR", tmp_path)
        catalog.builtin_signatures.cache_clear()
        try:
            assert catalog.builtin_signatures() == ()
        finally:
            monkeypatch.undo()
            catalog.builtin_signatures.cache_clear()


class TestBranchFixes:
    """Point releases that ship a branch's fix are not flagged."""

    @pytest.mark.parametrize(
        "version,affected",
        [
            ("3.21.9", True),
            ("3.21.10", False),
            ("3.22.7", True),
            ("3.22.8", False),
            ("3.23.7", True),
            ("3.23.8", False),
            ("3.24.3", True),
            ("3.24.4", False),
            ("3.19.4", True),
        ],
    )
    def test_branch_fixes(self, version, affected):
        name = f"demoos-{version}-x86_64-uefi-tiny-r0"
        hits = match_image(DEMO, "aws", [name], DEMO_PUBLISHER)
        assert bool(hits) is affected


class TestVersionRangesAndExamples:
    def test_several_ranges(self):
        rule = signature()["images"][0]
        rule.pop("version_min"), rule.pop("version_max")
        rule["versions"] = [{"min": "1.0", "max": "1.1"}, {"min": "2.0"}]
        demo = [ThreatSignature.model_validate(signature(images=[rule]))]
        hits = {
            name: bool(match_image(demo, "aws", [name]))
            for name in ("demo-1.1", "demo-1.5", "demo-2.0", "demo-9.9")
        }
        assert hits == {
            "demo-1.1": True,
            "demo-1.5": False,
            "demo-2.0": True,
            "demo-9.9": True,
        }

    @pytest.mark.parametrize(
        "versions",
        [[{}], [{"min": "2.0", "max": "1.0"}], [{"min": "not a version"}]],
    )
    def test_invalid_ranges(self, versions):
        rule = {
            "cloud": "aws",
            "name_regex": r"^d-(?P<version>\S+)$",
            "versions": versions,
        }
        with pytest.raises(ValidationError):
            ThreatSignature.model_validate(signature(images=[rule]))

    def test_examples_that_disagree_reject_the_signature(self):
        rule = signature()["images"][0] | {
            "examples": {"matches": ["demo-1.9"], "misses": ["demo-1.3"]}
        }
        with pytest.raises(ValidationError, match=r"demo-1\.9.*demo-1\.3"):
            ThreatSignature.model_validate(signature(images=[rule]))

    def test_examples_that_agree_pass(self):
        rule = signature()["images"][0] | {
            "examples": {"matches": ["demo-1.3"], "misses": ["demo-1.9", "x-1.3"]}
        }
        ThreatSignature.model_validate(signature(images=[rule]))

    def test_azure_miss_in_another_case_is_rejected_with_the_reason(self):
        # Azure matches in any case, so a miss that only changes the case is
        # an image the check flags: the error says why, since load_signatures
        # logs it when it skips a supplied signature.
        rule = {
            "cloud": "azure",
            "name_regex": r"^UbuntuServer-18\.04-",
            "examples": {
                "matches": ["UbuntuServer-18.04-LTS-latest"],
                "misses": ["ubuntuserver-18.04-lts-latest"],
            },
        }
        with pytest.raises(ValidationError, match="Azure names match in any case"):
            ThreatSignature.model_validate(signature(images=[rule]))

    def test_aws_miss_in_another_case_still_passes(self):
        rule = {
            "cloud": "aws",
            "name_regex": r"^UbuntuServer-18\.04-",
            "examples": {
                "matches": ["UbuntuServer-18.04-LTS-latest"],
                "misses": ["ubuntuserver-18.04-lts-latest"],
            },
        }
        ThreatSignature.model_validate(signature(images=[rule]))

    def test_overlong_names_are_cut_before_matching(self):
        rule = {"cloud": "aws", "name_regex": "z$"}
        demo = [ThreatSignature.model_validate(signature(images=[rule]))]
        assert match_image(demo, "aws", ["a" * 5000 + "z"]) == []


class TestExposurePorts:
    def test_port_is_shorthand_for_ports(self):
        demo = ThreatSignature.model_validate(signature(exposure={"port": 443}))
        assert demo.exposure.ports == [443]

    def test_port_and_ports_together_are_rejected(self):
        with pytest.raises(ValidationError):
            ThreatSignature.model_validate(
                signature(exposure={"port": 443, "ports": [443]})
            )

    def test_match_carries_every_port_and_the_open_one(self):
        demo = ThreatSignature.model_validate(
            signature(exposure={"protocol": "udp", "ports": [443, 8443]})
        )
        default = to_match(demo, "demo-1.3", "publisher")
        assert default.exposure_ports == [443, 8443]
        assert default.exposure_port == 443
        assert default.exposure_protocol == "udp"
        observed = to_match(
            demo, "demo-1.3", "publisher", exposed_to_internet=True, exposure_port=8443
        )
        assert observed.exposure_port == 8443
        assert "UDP 8443 open to the internet" in describe_matches([observed])

    @pytest.mark.parametrize("ports", [[], [0], [70000], list(range(1, 20))])
    def test_invalid_ports(self, ports):
        with pytest.raises(ValidationError):
            ThreatSignature.model_validate(signature(exposure={"ports": ports}))

    def test_too_many_cves_are_rejected(self):
        cves = [f"CVE-2026-{1000 + i}" for i in range(26)]
        with pytest.raises(ValidationError):
            ThreatSignature.model_validate(signature(cves=cves))


class TestRegexCost:
    """A signature's regex runs on every image of every scanned account."""

    @staticmethod
    def _rule_signature(name_regex, examples=None):
        rule = {"cloud": "aws", "name_regex": name_regex}
        if examples:
            rule["examples"] = examples
        return signature(images=[rule])

    def test_backtracking_pattern_matches_quickly(self):
        import time

        demo = [ThreatSignature.model_validate(self._rule_signature(r"^(\w+\s?)*$"))]
        start = time.monotonic()
        hits = match_image(demo, "aws", ["a" * 25 + "!"])
        assert hits == []
        assert time.monotonic() - start < 0.5

    def test_pattern_over_the_time_limit_is_skipped_not_raised(self, caplog):
        demo = [
            ThreatSignature.model_validate(
                self._rule_signature(r"^(a|aa)+$") | {"id": "slow-threat"}
            )
        ]
        assert match_image(demo, "aws", ["a" * 60 + "b"]) == []
        assert "slow-threat" in caplog.text

    def test_pattern_over_the_time_limit_on_its_examples_is_rejected(self):
        slow = self._rule_signature(r"^(a|aa)+$", examples={"misses": ["a" * 60 + "b"]})
        with pytest.raises(ValidationError, match="too long"):
            ThreatSignature.model_validate(slow)
