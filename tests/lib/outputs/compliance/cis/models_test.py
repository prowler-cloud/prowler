from prowler.lib.outputs.compliance.cis.models import CISBaseModel, AWSCISModel


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
        assert keys[0] == "Provider"
        assert keys[1] == "Description"
        # Provider-specific fields come after Description, before base fields
        provider_idx = keys.index("Provider")
        desc_idx = keys.index("Description")
        acct_idx = keys.index("AccountId")
        region_idx = keys.index("Region")
        assert desc_idx < acct_idx < region_idx
        # Base fields like AssessmentDate come after provider identity fields
        assessment_idx = keys.index("AssessmentDate")
        assert region_idx < assessment_idx

        # Exclude provider identity fields
        d_no_identity = model.dict(exclude={"AccountId", "Region"})
        assert "AccountId" not in d_no_identity
        assert "Region" not in d_no_identity
        keys_no_identity = list(d_no_identity.keys())
        assert keys_no_identity[0] == "Provider"
        assert keys_no_identity[1] == "Description"
        # After Description, the next field should be a base field
        assert keys_no_identity[2] == "AssessmentDate"
