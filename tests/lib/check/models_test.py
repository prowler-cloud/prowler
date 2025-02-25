from unittest import mock

import pytest

from prowler.lib.check.models import (
    Check_Report_AWS,
    Check_Report_Azure,
    Check_Report_GCP,
    Check_Report_Kubernetes,
    CheckMetadata,
    CheckReport,
)
from tests.lib.check.compliance_check_test import custom_compliance_metadata

mock_metadata = CheckMetadata(
    Provider="aws",
    CheckID="accessanalyzer_enabled",
    CheckTitle="Check 1",
    CheckType=["type1"],
    ServiceName="service1",
    SubServiceName="subservice1",
    ResourceIdTemplate="template1",
    Severity="high",
    ResourceType="resource1",
    Description="Description 1",
    Risk="risk1",
    RelatedUrl="url1",
    Remediation={
        "Code": {
            "CLI": "cli1",
            "NativeIaC": "native1",
            "Other": "other1",
            "Terraform": "terraform1",
        },
        "Recommendation": {"Text": "text1", "Url": "url1"},
    },
    Categories=["categoryone"],
    DependsOn=["dependency1"],
    RelatedTo=["related1"],
    Notes="notes1",
    Compliance=[],
)

mock_metadata_lambda = CheckMetadata(
    Provider="aws",
    CheckID="awslambda_function_url_public",
    CheckTitle="Check 1",
    CheckType=["type1"],
    ServiceName="lambda",
    SubServiceName="subservice1",
    ResourceIdTemplate="template1",
    Severity="high",
    ResourceType="resource1",
    Description="Description 1",
    Risk="risk1",
    RelatedUrl="url1",
    Remediation={
        "Code": {
            "CLI": "cli1",
            "NativeIaC": "native1",
            "Other": "other1",
            "Terraform": "terraform1",
        },
        "Recommendation": {"Text": "text1", "Url": "url1"},
    },
    Categories=["categoryone"],
    DependsOn=["dependency1"],
    RelatedTo=["related1"],
    Notes="notes1",
    Compliance=[],
)


class TestCheckMetada:
    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_get_bulk(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        result = CheckMetadata.get_bulk(provider="aws")

        # Assertions
        assert "accessanalyzer_enabled" in result.keys()
        assert result["accessanalyzer_enabled"] == mock_metadata
        mock_recover_checks.assert_called_once_with("aws")
        mock_load_metadata.assert_called_once_with(
            "/path/to/accessanalyzer_enabled/accessanalyzer_enabled.metadata.json"
        )

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata)

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_get(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata)

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_severity(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata, severity="high")

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_severity_not_values(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata, severity="low")

        # Assertions
        assert result == set()

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_category(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, category="categoryone"
        )

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_category_not_valid(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, category="categorytwo"
        )

        # Assertions
        assert result == set()

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_service(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, service="service1"
        )

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_service_lambda(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("awslambda_function_url_public", "/path/to/awslambda_function_url_public")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata_lambda

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, service="lambda"
        )

        # Assertions
        assert result == {"awslambda_function_url_public"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_service_awslambda(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("awslambda_function_url_public", "/path/to/awslambda_function_url_public")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata_lambda

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, service="awslambda"
        )

        # Assertions
        assert result == {"awslambda_function_url_public"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_service_invalid(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, service="service2"
        )

        # Assertions
        assert result == set()

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_compliance(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")
        bulk_compliance_frameworks = custom_compliance_metadata

        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata,
            bulk_compliance_frameworks=bulk_compliance_frameworks,
            compliance_framework="framework1_aws",
        )

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    def test_list_by_compliance_empty(self):
        bulk_compliance_frameworks = custom_compliance_metadata
        result = CheckMetadata.list(
            bulk_compliance_frameworks=bulk_compliance_frameworks,
            compliance_framework="framework1_azure",
        )

        # Assertions
        assert result == set()

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_only_check_metadata(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata)
        assert result == set()


class TestCheckReport:
    def test_check_report_resource_dict(self):
        resource = {"id": "test_id"}
        check_report = CheckReport(metadata=mock_metadata.json(), resource=resource)
        assert check_report.status == ""
        assert check_report.check_metadata == mock_metadata
        assert check_report.resource == resource
        assert check_report.status_extended == ""
        assert check_report.resource_details == ""
        assert check_report.resource_tags == []
        assert check_report.muted is False

    # def test_check_report_resource_dict_method(self):
    #     resource = mock.Mock()
    #     resource.dict = lambda: {"id": "test_id"}
    #     check_report = CheckReport(metadata=mock_metadata.json(), resource=resource)
    #     assert check_report.status == ""
    #     assert check_report.check_metadata == mock_metadata
    #     assert check_report.resource == {"id": "test_id"}
    #     assert check_report.status_extended == ""
    #     assert check_report.resource_details == ""
    #     assert check_report.resource_tags == []
    #     assert check_report.muted is False


class TestCheckReportAWS:
    def test_check_report_aws(self):
        resource = mock.Mock(spec=["id", "arn", "region"])
        resource.id = "test_id"
        resource.arn = "test_arn"
        resource.region = "test_region"
        check_report_aws = Check_Report_AWS(
            metadata=mock_metadata.json(), resource=resource
        )

        assert check_report_aws.resource_id == "test_id"
        assert check_report_aws.resource_arn == "test_arn"
        assert check_report_aws.region == "test_region"

    def test_check_report_aws_no_id_but_name(self):
        resource = mock.Mock(spec=["name", "arn", "region"])
        resource.name = "test_id"
        resource.arn = "test_arn"
        resource.region = "test_region"
        report = Check_Report_AWS(metadata=mock_metadata.json(), resource=resource)

        assert report.resource_id == "test_id"
        assert report.resource_arn == "test_arn"
        assert report.region == "test_region"

    def test_check_report_aws_no_id_or_name(self):
        resource = mock.Mock(spec=["arn", "region"])
        resource.arn = "test_arn"
        resource.region = "test_region"

        with pytest.raises(AttributeError):
            Check_Report_AWS(metadata=mock_metadata.json(), resource=resource)

    def test_check_report_aws_no_arn(self):
        resource = mock.Mock(spec=["id", "region"])
        resource.id = "test_id"
        resource.region = "test_region"

        with pytest.raises(AttributeError):
            Check_Report_AWS(metadata=mock_metadata.json(), resource=resource)

    def test_check_report_aws_no_region(self):
        resource = mock.Mock(spec=["id", "arn"])
        resource.id = "test_id"
        resource.arn = "test_arn"

        with pytest.raises(AttributeError):
            Check_Report_AWS(metadata=mock_metadata.json(), resource=resource)

        # check finding without resource_id
        # raise log error
        # continue execution


class TestCheckReportAzure:
    def test_check_report_azure(self):
        resource = mock.Mock(spec=["id", "name", "location"])
        resource.id = "test_id"
        resource.name = "test_name"
        resource.location = "test_location"
        report = Check_Report_Azure(metadata=mock_metadata.json(), resource=resource)

        assert report.resource_id == "test_id"
        assert report.resource_name == "test_name"
        assert report.location == "test_location"
        assert report.subscription is None

    def test_check_report_azure_no_id(self):
        resource = mock.Mock(spec=["name", "location"])
        resource.name = "test_name"
        resource.location = "global"

        with pytest.raises(AttributeError):
            Check_Report_Azure(metadata=mock_metadata.json(), resource=resource)

    def test_check_report_azure_resource_id(self):
        resource = mock.Mock(spec=["resource_id", "name", "location"])
        resource.resource_id = "resource_id"
        resource.name = "test_name"
        resource.location = "global"
        report = Check_Report_Azure(metadata=mock_metadata.json(), resource=resource)

        assert report.resource_id == "resource_id"
        assert report.resource_name == "test_name"
        assert report.location == "global"
        assert report.subscription is None

    def test_check_report_azure_no_name(self):
        resource = mock.Mock(spec=["id", "location"])
        resource.id = "test_id"
        resource.location = "global"

        with pytest.raises(AttributeError):
            Check_Report_Azure(metadata=mock_metadata.json(), resource=resource)

    def test_check_report_azure_resource_name(self):
        resource = mock.Mock(spec=["id", "resource_name", "location"])
        resource.id = "test_id"
        resource.resource_name = "test_name"
        resource.location = "global"
        report = Check_Report_Azure(metadata=mock_metadata.json(), resource=resource)

        assert report.resource_id == "test_id"
        assert report.resource_name == "test_name"
        assert report.location == "global"
        assert report.subscription is None

    def test_check_report_azure_no_location(self):
        resource = mock.Mock(spec=["id", "name"])
        resource.id = "test_id"
        resource.name = "test_name"
        report = Check_Report_Azure(metadata=mock_metadata.json(), resource=resource)

        assert report.resource_id == "test_id"
        assert report.resource_name == "test_name"
        assert report.location == "global"
        assert report.subscription is None


class TestCheckReportGCP:
    def test_check_report_gcp(self):
        resource = mock.Mock(spec=["id", "name", "project_id", "location"])
        resource.id = "test_id"
        resource.name = "test_name"
        resource.project_id = "test_project"
        resource.location = "test_location"
        report = Check_Report_GCP(metadata=mock_metadata.json(), resource=resource)

        assert report.resource_id == "test_id"
        assert report.resource_name == "test_name"
        assert report.location == "test_location"
        assert report.project_id == "test_project"

    def test_check_report_gcp_resource_id(self):
        resource = mock.Mock(spec=["id", "name", "project_id", "location"])
        resource.id = "test_id"
        resource.name = "test_name"
        resource.project_id = "test_project"
        resource.location = "test_location"
        report = Check_Report_GCP(
            metadata=mock_metadata.json(), resource=resource, resource_id="resource_1"
        )

        assert report.resource_id == "resource_1"
        assert report.resource_name == "test_name"
        assert report.location == "test_location"
        assert report.project_id == "test_project"

    def test_check_report_gcp_no_resource_id(self):
        resource = mock.Mock(spec=["name", "project_id", "location"])
        resource.name = "test_name"
        resource.project_id = "test_project"
        resource.location = "test_location"
        report = Check_Report_GCP(
            metadata=mock_metadata.json(),
            resource=resource,
        )

        assert report.resource_id == "test_name"
        assert report.resource_name == "test_name"
        assert report.location == "test_location"
        assert report.project_id == "test_project"

    def test_check_report_gcp_resource_name(self):
        resource = mock.Mock(spec=["id", "name", "project_id", "location"])
        resource.id = "test_id"
        resource.name = "test_name"
        resource.project_id = "test_project"
        resource.location = "test_location"
        report = Check_Report_GCP(
            metadata=mock_metadata.json(), resource=resource, resource_name="resource_1"
        )

        assert report.resource_id == "test_id"
        assert report.resource_name == "resource_1"
        assert report.location == "test_location"
        assert report.project_id == "test_project"

    def test_check_report_gcp_no_project_id(self):
        resource = mock.Mock(spec=["id", "name", "location"])
        resource.id = "test_id"
        resource.name = "test_name"
        resource.location = "test_location"

        with pytest.raises(AttributeError):
            Check_Report_GCP(metadata=mock_metadata.json(), resource=resource)

    def test_check_report_gcp_no_location(self):
        resource = mock.Mock(spec=["id", "name", "project_id"])
        resource.id = "test_id"
        resource.name = "test_name"
        resource.project_id = "test_project"

        with pytest.raises(AttributeError):
            Check_Report_GCP(metadata=mock_metadata.json(), resource=resource)

    def test_check_report_gcp_region(self):
        resource = mock.Mock(spec=["id", "name", "region", "project_id"])
        resource.id = "test_id"
        resource.name = "test_name"
        resource.region = "test_region"
        resource.project_id = "test_project"
        report = Check_Report_GCP(
            metadata=mock_metadata.json(),
            resource=resource,
        )

        assert report.resource_id == "test_id"
        assert report.resource_name == "test_name"
        assert report.location == "test_region"
        assert report.project_id == "test_project"


class TestCheckReportKubernetes:
    def test_check_report_kubernetes(self):
        resource = mock.Mock(spec=["uid", "name", "namespace"])
        resource.uid = "test_uid"
        resource.name = "test_name"
        resource.namespace = "test_namespace"
        report = Check_Report_Kubernetes(
            metadata=mock_metadata.json(), resource=resource
        )

        assert report.resource_id == "test_uid"
        assert report.resource_name == "test_name"
        assert report.namespace == "test_namespace"

    def test_check_report_kubernetes_no_name(self):
        resource = mock.Mock(spec=["uid", "namespace"])
        resource.uid = "test_uid"
        resource.namespace = "test_namespace"

        with pytest.raises(AttributeError):
            Check_Report_Kubernetes(metadata=mock_metadata.json(), resource=resource)

    def test_check_report_kubernetes_no_uid(self):
        resource = mock.Mock(spec=["name", "namespace"])
        resource.name = "test_name"
        resource.namespace = "test_namespace"
        report = Check_Report_Kubernetes(
            metadata=mock_metadata.json(), resource=resource
        )

        assert report.resource_id == "test_name"
        assert report.resource_name == "test_name"
        assert report.namespace == "test_namespace"

    def test_check_report_kubernetes_no_namespace(self):
        resource = mock.Mock(spec=["name"])
        resource.name = "test_name"
        report = Check_Report_Kubernetes(
            metadata=mock_metadata.json(), resource=resource
        )

        assert report.resource_id == "test_name"
        assert report.resource_name == "test_name"
        assert report.namespace == "cluster-wide"
