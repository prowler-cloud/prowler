import json
from datetime import datetime, timezone
from types import SimpleNamespace

from py_ocsf_models.events.base_event import StatusID as EventStatusID
from py_ocsf_models.events.findings.compliance_finding import ComplianceFinding
from py_ocsf_models.events.findings.compliance_finding_type_id import (
    ComplianceFindingTypeID,
)
from py_ocsf_models.objects.compliance_status import StatusID as ComplianceStatusID

from prowler.lib.check.compliance_models import (
    AttributeMetadata,
    ComplianceFramework,
    OutputFormats,
    OutputsConfig,
    TableConfig,
    UniversalComplianceRequirement,
)
from prowler.lib.outputs.compliance.universal.ocsf_compliance import (
    OCSFComplianceOutput,
    _sanitize_resource_data,
)


def _make_finding(check_id, status="PASS", provider="aws"):
    """Create a mock Finding with all fields needed by OCSFComplianceOutput."""
    finding = SimpleNamespace()
    finding.provider = provider
    finding.account_uid = "123456789012"
    finding.account_name = "test-account"
    finding.account_email = ""
    finding.account_organization_uid = "org-123"
    finding.account_organization_name = "test-org"
    finding.account_tags = {"env": "test"}
    finding.region = "us-east-1"
    finding.status = status
    finding.status_extended = f"{check_id} is {status}"
    finding.resource_uid = f"arn:aws:iam::123456789012:{check_id}"
    finding.resource_name = check_id
    finding.resource_details = "some details"
    finding.resource_metadata = {}
    finding.resource_tags = {"Name": "test"}
    finding.partition = "aws"
    finding.muted = False
    finding.check_id = check_id
    finding.uid = "test-finding-uid"
    finding.timestamp = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    finding.prowler_version = "5.0.0"
    finding.compliance = {}
    finding.metadata = SimpleNamespace(
        Provider=provider,
        CheckID=check_id,
        CheckTitle=f"Title for {check_id}",
        CheckType=["test-type"],
        Description=f"Description for {check_id}",
        Severity="medium",
        ServiceName="iam",
        ResourceType="aws-iam-role",
        Risk="test-risk",
        RelatedUrl="https://example.com",
        Remediation=SimpleNamespace(
            Recommendation=SimpleNamespace(Text="Fix it", Url="https://fix.com"),
        ),
        DependsOn=[],
        RelatedTo=[],
        Categories=["test"],
        Notes="",
        AdditionalURLs=[],
    )
    return finding


def _make_framework(requirements, attrs_metadata=None):
    return ComplianceFramework(
        framework="TestFW",
        name="Test Framework",
        provider="AWS",
        version="1.0",
        description="Test framework",
        requirements=requirements,
        attributes_metadata=attrs_metadata,
        outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
    )


def _simple_requirement(req_id="REQ-1", checks=None):
    if checks is None:
        checks_dict = {"aws": ["check_a"]}
    elif isinstance(checks, dict):
        checks_dict = checks
    else:
        checks_dict = {"aws": list(checks)} if checks else {}
    return UniversalComplianceRequirement(
        id=req_id,
        description=f"Description for {req_id}",
        attributes={},
        checks=checks_dict,
    )


class TestOCSFComplianceOutput:
    def test_transform_basic(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert len(output.data) == 1
        assert isinstance(output.data[0], ComplianceFinding)

    def test_class_uid(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert output.data[0].class_uid == 2003

    def test_type_uid(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert output.data[0].type_uid == ComplianceFindingTypeID.Create
        assert output.data[0].type_uid == 200301

    def test_compliance_object_fields(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        compliance = output.data[0].compliance
        assert compliance.standards == ["TestFW-1.0"]
        assert compliance.requirements == ["REQ-1"]
        assert compliance.control == "Description for REQ-1"
        assert compliance.status_id == ComplianceStatusID.Pass

    def test_check_object_fields(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a", "FAIL")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        checks = output.data[0].compliance.checks
        assert len(checks) == 1
        assert checks[0].uid == "check_a"
        assert checks[0].name == "Title for check_a"
        assert checks[0].status == "FAIL"
        assert checks[0].status_id == ComplianceStatusID.Fail

    def test_finding_info_fields(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        info = output.data[0].finding_info
        assert info.uid == "test-finding-uid-REQ-1"
        assert info.title == "REQ-1"
        assert info.desc == "Description for REQ-1"

    def test_metadata_fields(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        metadata = output.data[0].metadata
        assert metadata.product.name == "Prowler"
        assert metadata.product.uid == "prowler"
        assert metadata.event_code == "check_a"

    def test_status_mapping_pass(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert output.data[0].compliance.status_id == ComplianceStatusID.Pass

    def test_status_mapping_fail(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a", "FAIL")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert output.data[0].compliance.status_id == ComplianceStatusID.Fail

    def test_manual_requirement(self):
        req = _simple_requirement("MANUAL-1", checks=[])
        fw = _make_framework([req])
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert len(output.data) == 1
        cf = output.data[0]
        assert cf.compliance.status_id == ComplianceStatusID.Unknown
        assert cf.status_code == "MANUAL"
        assert cf.finding_info.uid == "manual-MANUAL-1"

    def test_multi_provider_checks_dict(self):
        req = UniversalComplianceRequirement(
            id="REQ-1",
            description="Multi-provider req",
            attributes={},
            checks={"aws": ["check_a"], "azure": ["check_b"]},
        )
        fw = _make_framework([req])
        findings = [_make_finding("check_a", "PASS", provider="aws")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert len(output.data) == 1
        assert output.data[0].compliance.checks[0].uid == "check_a"

    def test_empty_findings(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])

        output = OCSFComplianceOutput(findings=[], framework=fw, provider="aws")

        assert output.data == []

    def test_cloud_info_in_unmapped(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a", provider="aws")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        cf = output.data[0]
        assert cf.unmapped is not None
        assert cf.unmapped["cloud"]["provider"] == "aws"
        assert cf.unmapped["cloud"]["account"]["uid"] == "123456789012"
        assert cf.unmapped["cloud"]["account"]["name"] == "test-account"

    def test_resources_populated(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        resources = output.data[0].resources
        assert len(resources) == 1
        assert resources[0].name == "check_a"
        assert resources[0].uid == "arn:aws:iam::123456789012:check_a"
        assert resources[0].type == "aws-iam-role"

    def test_batch_write_to_file(self, tmp_path):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [_make_finding("check_a", "PASS")]
        filepath = str(tmp_path / "compliance.ocsf.json")

        output = OCSFComplianceOutput(
            findings=findings, framework=fw, file_path=filepath, provider="aws"
        )
        output.batch_write_data_to_file()

        with open(filepath) as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["class_uid"] == 2003
        assert data[0]["compliance"]["standards"] == ["TestFW-1.0"]
        assert data[0]["compliance"]["requirements"] == ["REQ-1"]

    def test_multiple_findings_same_requirement(self):
        fw = _make_framework([_simple_requirement("REQ-1", ["check_a"])])
        findings = [
            _make_finding("check_a", "PASS"),
            _make_finding("check_a", "FAIL"),
        ]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert len(output.data) == 2
        statuses = [cf.compliance.status_id for cf in output.data]
        assert ComplianceStatusID.Pass in statuses
        assert ComplianceStatusID.Fail in statuses

    def test_requirement_attributes_in_unmapped(self):
        req = UniversalComplianceRequirement(
            id="REQ-1",
            description="Test requirement",
            attributes={"Section": "IAM", "Profile": "Level 1"},
            checks={"aws": ["check_a"]},
        )
        fw = _make_framework([req])
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        cf = output.data[0]
        assert cf.unmapped is not None
        assert "requirement_attributes" in cf.unmapped
        assert cf.unmapped["requirement_attributes"]["section"] == "IAM"
        assert cf.unmapped["requirement_attributes"]["profile"] == "Level 1"

    def test_requirement_attributes_keys_are_snake_case(self):
        req = UniversalComplianceRequirement(
            id="REQ-1",
            description="Test requirement",
            attributes={"Section": "IAM", "CCMLite": "Yes", "SubSection": "1.1"},
            checks={"aws": ["check_a"]},
        )
        fw = _make_framework([req])
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        attrs = output.data[0].unmapped["requirement_attributes"]
        assert "section" in attrs
        assert "ccm_lite" in attrs
        assert "sub_section" in attrs

    def test_requirement_attributes_empty_attrs_excluded(self):
        req = _simple_requirement("REQ-1", checks=["check_a"])
        fw = _make_framework([req])
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        cf = output.data[0]
        # Cloud info is still present, but no requirement_attributes key
        assert cf.unmapped is not None
        assert "cloud" in cf.unmapped
        assert "requirement_attributes" not in cf.unmapped

    def test_manual_requirement_has_attributes_in_unmapped(self):
        req = UniversalComplianceRequirement(
            id="MANUAL-1",
            description="Manual check",
            attributes={"Section": "Logging", "Type": "manual"},
            checks={},
        )
        fw = _make_framework([req])
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        assert len(output.data) == 1
        cf = output.data[0]
        assert cf.unmapped is not None
        assert cf.unmapped["requirement_attributes"]["section"] == "Logging"
        assert cf.unmapped["requirement_attributes"]["type"] == "manual"
        # Manual findings have no cloud info (finding is None)
        assert "cloud" not in cf.unmapped

    def test_ocsf_metadata_filters_attributes(self):
        """Attributes with output_formats.ocsf=False should be excluded from unmapped."""
        metadata = [
            AttributeMetadata(
                key="Section",
                type="str",
                output_formats=OutputFormats(ocsf=True),
            ),
            AttributeMetadata(
                key="InternalNote",
                type="str",
                output_formats=OutputFormats(ocsf=False),
            ),
            AttributeMetadata(
                key="Profile",
                type="str",
                output_formats=OutputFormats(ocsf=True),
            ),
        ]
        req = UniversalComplianceRequirement(
            id="REQ-1",
            description="Test",
            attributes={
                "Section": "IAM",
                "InternalNote": "skip me",
                "Profile": "Level 1",
            },
            checks={"aws": ["check_a"]},
        )
        fw = _make_framework([req], attrs_metadata=metadata)
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        attrs = output.data[0].unmapped["requirement_attributes"]
        assert "section" in attrs
        assert "profile" in attrs
        assert "internal_note" not in attrs

    def test_ocsf_metadata_all_false_excludes_all(self):
        """When all attributes have output_formats.ocsf=False, requirement_attributes should be empty."""
        metadata = [
            AttributeMetadata(
                key="Section", type="str", output_formats=OutputFormats(ocsf=False)
            ),
        ]
        req = UniversalComplianceRequirement(
            id="REQ-1",
            description="Test",
            attributes={"Section": "IAM"},
            checks={"aws": ["check_a"]},
        )
        fw = _make_framework([req], attrs_metadata=metadata)
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        cf = output.data[0]
        assert cf.unmapped is not None
        # requirement_attributes should not appear since all attrs are filtered out
        assert "requirement_attributes" not in cf.unmapped

    def test_ocsf_no_metadata_includes_all(self):
        """Without attributes_metadata, all attributes should be included (backward compat)."""
        req = UniversalComplianceRequirement(
            id="REQ-1",
            description="Test",
            attributes={"Section": "IAM", "Custom": "value"},
            checks={"aws": ["check_a"]},
        )
        fw = _make_framework([req], attrs_metadata=None)
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        attrs = output.data[0].unmapped["requirement_attributes"]
        assert "section" in attrs
        assert "custom" in attrs

    def test_ocsf_default_is_true(self):
        """output_formats.ocsf defaults to True — attributes are included unless explicitly excluded."""
        metadata = [
            AttributeMetadata(key="Section", type="str"),
            AttributeMetadata(key="Profile", type="str"),
        ]
        req = UniversalComplianceRequirement(
            id="REQ-1",
            description="Test",
            attributes={"Section": "IAM", "Profile": "Level 1"},
            checks={"aws": ["check_a"]},
        )
        fw = _make_framework([req], attrs_metadata=metadata)
        findings = [_make_finding("check_a", "PASS")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        attrs = output.data[0].unmapped["requirement_attributes"]
        assert "section" in attrs
        assert "profile" in attrs

    def test_ocsf_filter_on_manual_requirements(self):
        """OCSF filtering should also apply to manual requirements."""
        metadata = [
            AttributeMetadata(
                key="Section", type="str", output_formats=OutputFormats(ocsf=True)
            ),
            AttributeMetadata(
                key="InternalNote",
                type="str",
                output_formats=OutputFormats(ocsf=False),
            ),
        ]
        req = UniversalComplianceRequirement(
            id="MANUAL-1",
            description="Manual",
            attributes={"Section": "Logging", "InternalNote": "hidden"},
            checks={},
        )
        fw = _make_framework([req], attrs_metadata=metadata)
        findings = [_make_finding("check_a")]

        output = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")

        cf = output.data[0]
        assert cf.unmapped["requirement_attributes"]["section"] == "Logging"
        assert "internal_note" not in cf.unmapped["requirement_attributes"]


class TestSanitizeResourceData:
    """Unit tests for the _sanitize_resource_data helper.

    Service resources may carry non-JSON-serializable objects (e.g. raw
    Pydantic models such as ``Trail`` or ``LifecyclePolicy``). The helper
    must convert them so the resulting ComplianceFinding can be serialized.
    """

    def test_dict_passthrough(self):
        result = _sanitize_resource_data("details", {"a": 1, "b": "two"})
        assert result == {"details": "details", "metadata": {"a": 1, "b": "two"}}

    def test_none_metadata(self):
        result = _sanitize_resource_data("details", None)
        assert result == {"details": "details", "metadata": None}

    def test_pydantic_v2_model_dump(self):
        class FakeV2Model:
            def model_dump(self):
                return {"name": "trail-1", "region": "us-east-1"}

        result = _sanitize_resource_data("d", {"trail": FakeV2Model()})
        assert result["metadata"]["trail"] == {
            "name": "trail-1",
            "region": "us-east-1",
        }

    def test_pydantic_v1_dict(self):
        class FakeV1Model:
            def dict(self):
                return {"name": "policy-1", "schedule": "daily"}

        result = _sanitize_resource_data("d", {"policy": FakeV1Model()})
        assert result["metadata"]["policy"] == {
            "name": "policy-1",
            "schedule": "daily",
        }

    def test_nested_pydantic_in_list(self):
        class FakeModel:
            def model_dump(self):
                return {"id": "x"}

        result = _sanitize_resource_data("d", {"items": [FakeModel(), FakeModel()]})
        assert result["metadata"]["items"] == [{"id": "x"}, {"id": "x"}]

    def test_nested_dict_recursion(self):
        class FakeInner:
            def model_dump(self):
                return {"k": "v"}

        result = _sanitize_resource_data(
            "d", {"outer": {"inner": FakeInner(), "x": [1, 2]}}
        )
        assert result["metadata"]["outer"]["inner"] == {"k": "v"}
        assert result["metadata"]["outer"]["x"] == [1, 2]

    def test_tuple_to_list(self):
        result = _sanitize_resource_data("d", {"t": (1, 2, "three")})
        assert result["metadata"]["t"] == [1, 2, "three"]

    def test_non_string_dict_keys_coerced(self):
        result = _sanitize_resource_data("d", {1: "a", 2: "b"})
        assert result["metadata"] == {"1": "a", "2": "b"}

    def test_unknown_object_falls_back_to_str(self):
        class Opaque:
            def __str__(self):
                return "opaque-repr"

        result = _sanitize_resource_data("d", {"thing": Opaque()})
        assert result["metadata"]["thing"] == "opaque-repr"

    def test_circular_reference_falls_back_to_empty(self):
        a = {}
        a["self"] = a
        # json.dumps raises ValueError on recursion → fallback to empty metadata
        result = _sanitize_resource_data("d", a)
        assert result == {"details": "d", "metadata": {}}

    def test_serializes_via_full_finding_pipeline(self):
        """End-to-end: a finding with a non-serializable resource_metadata
        produces a JSON-serializable ComplianceFinding."""

        class TrailLike:
            def __init__(self):
                self.name = "trail-A"
                self.kms_key_id = "arn:aws:kms:..."

            def model_dump(self):
                return {"name": self.name, "kms_key_id": self.kms_key_id}

        finding = _make_finding("check_a")
        finding.resource_metadata = {"trail": TrailLike()}
        req = _simple_requirement()
        fw = _make_framework([req])

        output = OCSFComplianceOutput(findings=[finding], framework=fw, provider="aws")

        # Serialize the resulting ComplianceFinding — must NOT raise
        cf = output.data[0]
        if hasattr(cf, "model_dump_json"):
            json_output = cf.model_dump_json(exclude_none=True)
        else:
            json_output = cf.json(exclude_none=True)
        payload = json.loads(json_output)

        # Confirm the trail object made it through as a plain dict
        assert payload["resources"][0]["data"]["metadata"]["trail"]["name"] == "trail-A"


class TestEventStatusInline:
    """Tests for the inlined event_status logic that replaced
    OCSF.get_finding_status_id() to break the cyclic import."""

    def test_unmuted_finding_status_new(self):
        finding = _make_finding("check_a")
        finding.muted = False
        req = _simple_requirement()
        fw = _make_framework([req])

        output = OCSFComplianceOutput(findings=[finding], framework=fw, provider="aws")
        cf = output.data[0]

        assert cf.status_id == EventStatusID.New.value
        assert cf.status == EventStatusID.New.name

    def test_muted_finding_status_suppressed(self):
        finding = _make_finding("check_a")
        finding.muted = True
        req = _simple_requirement()
        fw = _make_framework([req])

        output = OCSFComplianceOutput(findings=[finding], framework=fw, provider="aws")
        cf = output.data[0]

        assert cf.status_id == EventStatusID.Suppressed.value
        assert cf.status == EventStatusID.Suppressed.name


class TestNoTopLevelOCSFImport:
    """Regression test: the top-level OCSF/Finding imports were removed
    to break the CodeQL cyclic-import warnings. Ensure they stay out of
    the runtime namespace of the module (TYPE_CHECKING block only)."""

    def test_finding_not_in_runtime_namespace(self):
        import prowler.lib.outputs.compliance.universal.ocsf_compliance as mod

        assert "Finding" not in dir(mod)

    def test_ocsf_class_not_imported(self):
        import prowler.lib.outputs.compliance.universal.ocsf_compliance as mod

        assert "OCSF" not in dir(mod)
