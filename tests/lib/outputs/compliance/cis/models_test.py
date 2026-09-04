from prowler.lib.outputs.compliance.cis.models import (
    AWSCISModel,
    CISBaseModel,
    GCPCISModel,
    GithubCISModel,
    KubernetesCISModel,
)


class TestCISBaseModel:
    def test_dict_serialization_order(self):
        """Test that CISBaseModel.dict serializes fields in expected order."""
        model = CISBaseModel(
            Provider="aws",
            Description="test",
            AssessmentDate="2023-01-01",
            Requirements_Id="1.1",
            Requirements_Description="req desc",
            Requirements_Attributes_Section="section",
            Requirements_Attributes_AssessmentStatus="status",
            Requirements_Attributes_Description="desc",
            Requirements_Attributes_RationaleStatement="rat",
            Requirements_Attributes_ImpactStatement="imp",
            Requirements_Attributes_RemediationProcedure="rem",
            Requirements_Attributes_AuditProcedure="aud",
            Requirements_Attributes_AdditionalInformation="add",
            Requirements_Attributes_References="ref",
            Status="PASS",
            StatusExtended="PASS",
            ResourceId="id",
            ResourceName="name",
            CheckId="check",
            Muted=False,
            Framework="cis",
            Name="name",
        )

        # Test full dictionary output
        d = model.dict()
        keys = list(d.keys())
        assert keys[0] == "Provider"
        assert keys[1] == "Description"

        # Test filtered dictionary without Provider
        d_no_provider = model.dict(exclude={"Provider"})
        assert "Provider" not in d_no_provider
        keys_no_prov = list(d_no_provider.keys())
        assert keys_no_prov[0] == "Description"

        # Test filtered dictionary without Description
        d_no_desc = model.dict(exclude={"Description"})
        assert "Description" not in d_no_desc
        keys_no_desc = list(d_no_desc.keys())
        assert keys_no_desc[0] == "Provider"

        # Test filtered dictionary without either
        d_no_both = model.dict(exclude={"Provider", "Description"})
        assert "Provider" not in d_no_both
        assert "Description" not in d_no_both

    def test_provider_specific_field_ordering(self):
        """Test that provider identity fields appear between Description and base fields."""
        model = AWSCISModel(
            Provider="aws",
            Description="test",
            AccountId="123456789012",
            Region="us-east-1",
            AssessmentDate="2023-01-01",
            Requirements_Id="1.1",
            Requirements_Description="req desc",
            Requirements_Attributes_Section="section",
            Requirements_Attributes_AssessmentStatus="status",
            Requirements_Attributes_Description="desc",
            Requirements_Attributes_RationaleStatement="rat",
            Requirements_Attributes_ImpactStatement="imp",
            Requirements_Attributes_RemediationProcedure="rem",
            Requirements_Attributes_AuditProcedure="aud",
            Requirements_Attributes_AdditionalInformation="add",
            Requirements_Attributes_References="ref",
            Status="PASS",
            StatusExtended="PASS",
            ResourceId="id",
            ResourceName="name",
            CheckId="check",
            Muted=False,
            Framework="cis",
            Name="name",
        )

        d = model.dict()
        keys = list(d.keys())
        expected_keys = [
            "Provider",
            "Description",
            "AccountId",
            "Region",
            "AssessmentDate",
            "Requirements_Id",
            "Requirements_Description",
            "Requirements_Attributes_Section",
            "Requirements_Attributes_SubSection",
            "Requirements_Attributes_Profile",
            "Requirements_Attributes_AssessmentStatus",
            "Requirements_Attributes_Description",
            "Requirements_Attributes_RationaleStatement",
            "Requirements_Attributes_ImpactStatement",
            "Requirements_Attributes_RemediationProcedure",
            "Requirements_Attributes_AuditProcedure",
            "Requirements_Attributes_AdditionalInformation",
            "Requirements_Attributes_DefaultValue",
            "Requirements_Attributes_References",
            "Status",
            "StatusExtended",
            "ResourceId",
            "ResourceName",
            "CheckId",
            "Muted",
            "Framework",
            "Name",
        ]
        assert keys == expected_keys

        # Exclude provider identity fields
        d_no_identity = model.dict(exclude={"AccountId", "Region"})
        assert "AccountId" not in d_no_identity
        assert "Region" not in d_no_identity
        keys_no_identity = list(d_no_identity.keys())
        assert keys_no_identity[0] == "Provider"
        assert keys_no_identity[1] == "Description"
        assert keys_no_identity[2] == "AssessmentDate"

    def test_gcp_kubernetes_github_cis_ordering(self):
        """Test specific field exclusions and ordering for GCP, Kubernetes, and GitHub CIS models."""
        gcp_model = GCPCISModel(
            Provider="gcp",
            Description="test",
            ProjectId="project-123",
            Location="global",
            AssessmentDate="2023-01-01",
            Requirements_Id="1.1",
            Requirements_Description="req desc",
            Requirements_Attributes_Section="section",
            Requirements_Attributes_AssessmentStatus="status",
            Requirements_Attributes_Description="desc",
            Requirements_Attributes_RationaleStatement="rat",
            Requirements_Attributes_ImpactStatement="imp",
            Requirements_Attributes_RemediationProcedure="rem",
            Requirements_Attributes_AuditProcedure="aud",
            Requirements_Attributes_AdditionalInformation="add",
            Requirements_Attributes_References="ref",
            Status="PASS",
            StatusExtended="PASS",
            ResourceId="id",
            ResourceName="name",
            CheckId="check",
            Muted=False,
            Framework="cis",
            Name="name",
        )
        gcp_keys = list(gcp_model.dict().keys())
        assert "Requirements_Attributes_DefaultValue" not in gcp_keys
        assert gcp_keys[2:4] == ["ProjectId", "Location"]

        k8s_model = KubernetesCISModel(
            Provider="kubernetes",
            Description="test",
            Cluster="cluster",
            Context="ctx",
            Namespace="default",
            AssessmentDate="2023-01-01",
            Requirements_Id="1.1",
            Requirements_Description="req desc",
            Requirements_Attributes_Section="section",
            Requirements_Attributes_AssessmentStatus="status",
            Requirements_Attributes_Description="desc",
            Requirements_Attributes_RationaleStatement="rat",
            Requirements_Attributes_ImpactStatement="imp",
            Requirements_Attributes_RemediationProcedure="rem",
            Requirements_Attributes_AuditProcedure="aud",
            Requirements_Attributes_AdditionalInformation="add",
            Requirements_Attributes_References="ref",
            Status="PASS",
            StatusExtended="PASS",
            ResourceId="id",
            ResourceName="name",
            CheckId="check",
            Muted=False,
            Framework="cis",
            Name="name",
        )
        k8s_keys = list(k8s_model.dict().keys())
        ref_idx = k8s_keys.index("Requirements_Attributes_References")
        def_idx = k8s_keys.index("Requirements_Attributes_DefaultValue")
        assert ref_idx < def_idx

        github_model = GithubCISModel(
            Provider="github",
            Description="test",
            Account_Name="org",
            Account_Id="123",
            AssessmentDate="2023-01-01",
            Requirements_Id="1.1",
            Requirements_Description="req desc",
            Requirements_Attributes_Section="section",
            Requirements_Attributes_AssessmentStatus="status",
            Requirements_Attributes_Description="desc",
            Requirements_Attributes_RationaleStatement="rat",
            Requirements_Attributes_ImpactStatement="imp",
            Requirements_Attributes_RemediationProcedure="rem",
            Requirements_Attributes_AuditProcedure="aud",
            Requirements_Attributes_AdditionalInformation="add",
            Requirements_Attributes_References="ref",
            Status="PASS",
            StatusExtended="PASS",
            ResourceId="id",
            ResourceName="name",
            CheckId="check",
            Muted=False,
            Framework="cis",
            Name="name",
        )
        github_keys = list(github_model.dict().keys())
        assert "Requirements_Attributes_SubSection" not in github_keys
        ref_idx = github_keys.index("Requirements_Attributes_References")
        def_idx = github_keys.index("Requirements_Attributes_DefaultValue")
        assert ref_idx < def_idx

