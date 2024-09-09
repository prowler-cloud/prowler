from unittest.mock import MagicMock, patch

from prowler.lib.outputs.finding import Finding, Severity, Status


def mock_get_provider_data_mapping_aws(_):
    return {
        "auth_method": "mock_auth",
        "timestamp": 1622520000,
        "account_uid": "mock_account_uid",
        "account_name": "mock_account_name",
        "account_email": "mock_account_email",
        "account_organization_uid": "mock_account_org_uid",
        "account_organization_name": "mock_account_org_name",
        "account_tags": {"tag1": "value1"},
        "finding_uid": "mock_finding_uid",
        "provider": "aws",
        "check_id": "mock_check_id",
        "check_title": "mock_check_title",
        "check_type": "mock_check_type",
        "status": Status.PASS,
        "status_extended": "mock_status_extended",
        "muted": False,
        "service_name": "mock_service_name",
        "subservice_name": "mock_subservice_name",
        "severity": Severity.high,
        "resource_type": "mock_resource_type",
        "resource_uid": "mock_resource_uid",
        "resource_name": "mock_resource_name",
        "resource_details": "mock_resource_details",
        "resource_tags": {"tag1": "value1"},
        "partition": None,
        "region": "mock_region",
        "description": "mock_description",
        "risk": "mock_risk",
        "related_url": "mock_related_url",
        "remediation_recommendation_text": "mock_remediation_text",
        "remediation_recommendation_url": "mock_remediation_url",
        "remediation_code_nativeiac": "mock_code_nativeiac",
        "remediation_code_terraform": "mock_code_terraform",
        "remediation_code_cli": "mock_code_cli",
        "remediation_code_other": "mock_code_other",
        "compliance": {"mock_compliance_key": "mock_compliance_value"},
        "categories": "mock_categories",
        "depends_on": "mock_depends_on",
        "related_to": "mock_related_to",
        "notes": "mock_notes",
        "prowler_version": "1.0.0",
    }


def mock_get_provider_data_mapping_azure(_):
    return {
        "auth_method": "mock_auth",
        "timestamp": 1622520000,
        "account_uid": "mock_account_uid",
        "account_name": "mock_account_name",
        "account_email": "mock_account_email",
        "account_organization_uid": "mock_account_org_uid",
        "account_organization_name": "mock_account_org_name",
        "account_tags": {"tag1": "value1"},
        "finding_uid": "mock_finding_uid",
        "provider": "azure",
        "check_id": "mock_check_id",
        "check_title": "mock_check_title",
        "check_type": "mock_check_type",
        "status": Status.PASS,
        "status_extended": "mock_status_extended",
        "muted": False,
        "service_name": "mock_service_name",
        "subservice_name": "mock_subservice_name",
        "severity": Severity.high,
        "resource_type": "mock_resource_type",
        "resource_uid": "mock_resource_uid",
        "resource_name": "mock_resource_name",
        "resource_details": "mock_resource_details",
        "resource_tags": {"tag1": "value1"},
        "partition": None,
        "description": "mock_description",
        "risk": "mock_risk",
        "related_url": "mock_related_url",
        "remediation_recommendation_text": "mock_remediation_text",
        "remediation_recommendation_url": "mock_remediation_url",
        "remediation_code_nativeiac": "mock_code_nativeiac",
        "remediation_code_terraform": "mock_code_terraform",
        "remediation_code_cli": "mock_code_cli",
        "remediation_code_other": "mock_code_other",
        "compliance": {"mock_compliance_key": "mock_compliance_value"},
        "categories": "mock_categories",
        "depends_on": "mock_depends_on",
        "related_to": "mock_related_to",
        "notes": "mock_notes",
        "prowler_version": "1.0.0",
    }


def mock_get_provider_data_mapping_gcp(_):
    return {
        "auth_method": "mock_auth",
        "timestamp": 1622520000,
        "account_uid": "mock_account_uid",
        "account_name": "mock_account_name",
        "account_email": "mock_account_email",
        "account_organization_uid": "mock_account_org_uid",
        "account_organization_name": "mock_account_org_name",
        "account_tags": {"tag1": "value1"},
        "finding_uid": "mock_finding_uid",
        "provider": "gcp",
        "check_id": "mock_check_id",
        "check_title": "mock_check_title",
        "check_type": "mock_check_type",
        "status": Status.PASS,
        "status_extended": "mock_status_extended",
        "muted": False,
        "service_name": "mock_service_name",
        "subservice_name": "mock_subservice_name",
        "severity": Severity.high,
        "resource_type": "mock_resource_type",
        "resource_uid": "mock_resource_uid",
        "resource_name": "mock_resource_name",
        "resource_details": "mock_resource_details",
        "resource_tags": {"tag1": "value1"},
        "partition": None,
        "description": "mock_description",
        "risk": "mock_risk",
        "related_url": "mock_related_url",
        "remediation_recommendation_text": "mock_remediation_text",
        "remediation_recommendation_url": "mock_remediation_url",
        "remediation_code_nativeiac": "mock_code_nativeiac",
        "remediation_code_terraform": "mock_code_terraform",
        "remediation_code_cli": "mock_code_cli",
        "remediation_code_other": "mock_code_other",
        "compliance": {"mock_compliance_key": "mock_compliance_value"},
        "categories": "mock_categories",
        "depends_on": "mock_depends_on",
        "related_to": "mock_related_to",
        "notes": "mock_notes",
        "prowler_version": "1.0.0",
    }


def mock_get_provider_data_mapping_kubernetes(_):
    return {
        "auth_method": "mock_auth",
        "timestamp": 1622520000,
        "account_uid": "mock_account_uid",
        "account_name": "mock_account_name",
        "account_email": "mock_account_email",
        "account_organization_uid": "mock_account_org_uid",
        "account_organization_name": "mock_account_org_name",
        "account_tags": {"tag1": "value1"},
        "finding_uid": "mock_finding_uid",
        "provider": "kubernetes",
        "check_id": "mock_check_id",
        "check_title": "mock_check_title",
        "check_type": "mock_check_type",
        "status": Status.PASS,
        "status_extended": "mock_status_extended",
        "muted": False,
        "service_name": "mock_service_name",
        "subservice_name": "mock_subservice_name",
        "severity": Severity.high,
        "resource_type": "mock_resource_type",
        "resource_uid": "mock_resource_uid",
        "resource_name": "mock_resource_name",
        "resource_details": "mock_resource_details",
        "resource_tags": {"tag1": "value1"},
        "partition": None,
        "description": "mock_description",
        "risk": "mock_risk",
        "related_url": "mock_related_url",
        "remediation_recommendation_text": "mock_remediation_text",
        "remediation_recommendation_url": "mock_remediation_url",
        "remediation_code_nativeiac": "mock_code_nativeiac",
        "remediation_code_terraform": "mock_code_terraform",
        "remediation_code_cli": "mock_code_cli",
        "remediation_code_other": "mock_code_other",
        "compliance": {"mock_compliance_key": "mock_compliance_value"},
        "categories": "mock_categories",
        "depends_on": "mock_depends_on",
        "related_to": "mock_related_to",
        "notes": "mock_notes",
        "prowler_version": "1.0.0",
    }


def mock_fill_common_finding_data(_, unix_timestamp):
    return {"common_key": "common_value", "unix_timestamp": unix_timestamp}


def mock_get_check_compliance(_, __, ___):
    return {"mock_compliance_key": "mock_compliance_value"}


class TestFinding:
    @patch(
        "prowler.lib.outputs.finding.get_provider_data_mapping",
        new=mock_get_provider_data_mapping_aws,
    )
    @patch(
        "prowler.lib.outputs.finding.fill_common_finding_data",
        new=mock_fill_common_finding_data,
    )
    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_aws(self):
        # Mock provider and other arguments
        provider = MagicMock()
        provider.type = "aws"
        check_output = MagicMock()
        check_output.resource_id = "test_resource_id"
        check_output.resource_arn = "test_resource_arn"
        check_output.region = "us-west-1"
        output_options = MagicMock()
        output_options.unix_timestamp = 1234567890
        global_provider = MagicMock()
        global_provider.output_options = output_options
        # Call the method under test
        finding_output = Finding.generate_output(provider, check_output)

        # Assertions to verify expected behavior
        assert finding_output is not None
        assert finding_output.auth_method == "profile: mock_auth"
        assert finding_output.resource_name == "test_resource_id"
        assert finding_output.resource_uid == "test_resource_arn"
        assert finding_output.region == "us-west-1"
        assert finding_output.compliance == {
            "mock_compliance_key": "mock_compliance_value"
        }
        assert finding_output.provider == "aws"
        assert finding_output.check_id == "mock_check_id"
        assert finding_output.check_title == "mock_check_title"
        assert finding_output.check_type == "mock_check_type"
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.service_name == "mock_service_name"
        assert finding_output.subservice_name == "mock_subservice_name"
        assert finding_output.severity == Severity.high
        assert finding_output.resource_type == "mock_resource_type"
        assert finding_output.resource_tags == {"tag1": "value1"}
        assert finding_output.partition is None
        assert finding_output.description == "mock_description"
        assert finding_output.risk == "mock_risk"
        assert finding_output.related_url == "mock_related_url"
        assert finding_output.remediation_recommendation_text == "mock_remediation_text"
        assert finding_output.remediation_recommendation_url == "mock_remediation_url"
        assert finding_output.remediation_code_nativeiac == "mock_code_nativeiac"
        assert finding_output.remediation_code_terraform == "mock_code_terraform"
        assert finding_output.remediation_code_cli == "mock_code_cli"
        assert finding_output.remediation_code_other == "mock_code_other"
        assert finding_output.categories == "mock_categories"
        assert finding_output.depends_on == "mock_depends_on"
        assert finding_output.related_to == "mock_related_to"
        assert finding_output.notes == "mock_notes"
        assert finding_output.account_uid == "mock_account_uid"
        assert finding_output.account_name == "mock_account_name"
        assert finding_output.account_email == "mock_account_email"
        assert finding_output.account_organization_uid == "mock_account_org_uid"
        assert finding_output.account_organization_name == "mock_account_org_name"
        assert finding_output.account_tags == {"tag1": "value1"}
        assert finding_output.prowler_version == "1.0.0"

    @patch(
        "prowler.lib.outputs.finding.get_provider_data_mapping",
        new=mock_get_provider_data_mapping_azure,
    )
    @patch(
        "prowler.lib.outputs.finding.fill_common_finding_data",
        new=mock_fill_common_finding_data,
    )
    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_azure(self):
        # Mock provider and other arguments
        provider = MagicMock()
        provider.type = "azure"
        provider.identity.identity_type = "mock_identity_type"
        provider.identity.identity_id = "mock_identity_id"
        provider.identity.subscriptions = {
            "mock_subscription_id": "mock_subscription_name"
        }
        check_output = MagicMock()
        check_output.resource_id = "test_resource_id"
        check_output.resource_arn = "test_resource_arn"
        check_output.subscription = "mock_subscription_id"
        check_output.resource_name = "test_resource_name"
        check_output.location = "us-west-1"
        check_output.region = "us-west-1"
        output_options = MagicMock()
        output_options.unix_timestamp = 1234567890
        global_provider = MagicMock()
        global_provider.output_options = output_options
        # Call the method under test
        finding_output = Finding.generate_output(provider, check_output)

        # Assertions to verify expected behavior
        assert finding_output is not None
        assert finding_output.auth_method == "mock_identity_type: mock_identity_id"
        assert finding_output.resource_name == "test_resource_name"
        assert finding_output.resource_uid == "test_resource_id"
        assert finding_output.region == "us-west-1"
        assert finding_output.compliance == {
            "mock_compliance_key": "mock_compliance_value"
        }
        assert finding_output.provider == "azure"
        assert finding_output.check_id == "mock_check_id"
        assert finding_output.check_title == "mock_check_title"
        assert finding_output.check_type == "mock_check_type"
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.service_name == "mock_service_name"
        assert finding_output.subservice_name == "mock_subservice_name"
        assert finding_output.severity == Severity.high
        assert finding_output.resource_type == "mock_resource_type"
        assert finding_output.resource_tags == {"tag1": "value1"}
        assert finding_output.partition is None
        assert finding_output.description == "mock_description"
        assert finding_output.risk == "mock_risk"
        assert finding_output.related_url == "mock_related_url"
        assert finding_output.remediation_recommendation_text == "mock_remediation_text"
        assert finding_output.remediation_recommendation_url == "mock_remediation_url"
        assert finding_output.remediation_code_nativeiac == "mock_code_nativeiac"
        assert finding_output.remediation_code_terraform == "mock_code_terraform"
        assert finding_output.remediation_code_cli == "mock_code_cli"
        assert finding_output.remediation_code_other == "mock_code_other"
        assert finding_output.categories == "mock_categories"
        assert finding_output.depends_on == "mock_depends_on"

    @patch(
        "prowler.lib.outputs.finding.get_provider_data_mapping",
        new=mock_get_provider_data_mapping_gcp,
    )
    @patch(
        "prowler.lib.outputs.finding.fill_common_finding_data",
        new=mock_fill_common_finding_data,
    )
    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_gcp(self):
        provider = MagicMock()
        provider.type = "gcp"
        project = MagicMock()
        organization = MagicMock()
        organization.id = "mock_organization_id"
        organization.display_name = "mock_organization_name"
        project.id = "mock_project_id"
        project.name = "mock_project_name"
        project.labels = {"tag1": "value1"}
        project.organization = organization

        provider.projects = {"mock_project_id": project}
        check_output = MagicMock()
        check_output.resource_id = "test_resource_id"
        check_output.resource_arn = "test_resource_arn"
        check_output.region = "us-west-1"
        check_output.project_id = "mock_project_id"
        check_output.resource_name = "test_resource_name"
        check_output.location = "us-west-1"
        output_options = MagicMock()
        output_options.unix_timestamp = 1234567890

        finding_output = Finding.generate_output(provider, check_output)

        assert finding_output is not None
        assert finding_output.auth_method == "Principal: mock_auth"
        assert finding_output.resource_name == "test_resource_name"
        assert finding_output.resource_uid == "test_resource_id"
        assert finding_output.region == "us-west-1"
        assert finding_output.compliance == {
            "mock_compliance_key": "mock_compliance_value"
        }
        assert finding_output.provider == "gcp"
        assert finding_output.check_id == "mock_check_id"
        assert finding_output.check_title == "mock_check_title"
        assert finding_output.check_type == "mock_check_type"
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.service_name == "mock_service_name"
        assert finding_output.subservice_name == "mock_subservice_name"
        assert finding_output.severity == Severity.high
        assert finding_output.resource_type == "mock_resource_type"
        assert finding_output.resource_tags == {"tag1": "value1"}
        assert finding_output.partition is None
        assert finding_output.description == "mock_description"
        assert finding_output.risk == "mock_risk"
        assert finding_output.related_url == "mock_related_url"
        assert finding_output.remediation_recommendation_text == "mock_remediation_text"
        assert finding_output.remediation_recommendation_url == "mock_remediation_url"
        assert finding_output.remediation_code_nativeiac == "mock_code_nativeiac"
        assert finding_output.remediation_code_terraform == "mock_code_terraform"
        assert finding_output.remediation_code_cli == "mock_code_cli"
        assert finding_output.remediation_code_other == "mock_code_other"
        assert finding_output.categories == "mock_categories"
        assert finding_output.depends_on == "mock_depends_on"
        assert finding_output.related_to == "mock_related_to"
        assert finding_output.notes == "mock_notes"
        assert finding_output.account_uid == "mock_project_id"
        assert finding_output.account_name == "mock_project_name"
        assert finding_output.account_email == "mock_account_email"
        assert finding_output.account_organization_uid == "mock_organization_id"
        assert finding_output.account_organization_name == "mock_account_org_name"
        assert finding_output.account_tags == {"tag1": "value1"}
        assert finding_output.prowler_version == "1.0.0"
        assert finding_output.timestamp == 1622520000

    @patch(
        "prowler.lib.outputs.finding.get_provider_data_mapping",
        new=mock_get_provider_data_mapping_kubernetes,
    )
    @patch(
        "prowler.lib.outputs.finding.fill_common_finding_data",
        new=mock_fill_common_finding_data,
    )
    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_kubernetes(self):
        provider = MagicMock()
        provider.type = "kubernetes"
        identity = MagicMock()

        identity.context = "In-Cluster"
        provider.identity = identity
        check_output = MagicMock()
        check_output.resource_name = "test_resource_name"
        check_output.resource_id = "test_resource_id"
        check_output.namespace = "test_namespace"
        output_options = MagicMock()
        output_options.unix_timestamp = 1234567890

        finding_output = Finding.generate_output(provider, check_output)

        assert finding_output is not None
        assert finding_output.auth_method == "in-cluster"
        assert finding_output.resource_name == "test_resource_name"
        assert finding_output.resource_uid == "test_resource_id"
        assert finding_output.region == "namespace: test_namespace"
        assert finding_output.compliance == {
            "mock_compliance_key": "mock_compliance_value"
        }
        assert finding_output.provider == "kubernetes"
        assert finding_output.check_id == "mock_check_id"
        assert finding_output.check_title == "mock_check_title"
        assert finding_output.check_type == "mock_check_type"
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.service_name == "mock_service_name"
        assert finding_output.subservice_name == "mock_subservice_name"
        assert finding_output.severity == Severity.high
        assert finding_output.resource_type == "mock_resource_type"
        assert finding_output.resource_tags == {"tag1": "value1"}
        assert finding_output.partition is None
        assert finding_output.description == "mock_description"
        assert finding_output.risk == "mock_risk"
        assert finding_output.related_url == "mock_related_url"
        assert finding_output.remediation_recommendation_text == "mock_remediation_text"
        assert finding_output.remediation_recommendation_url == "mock_remediation_url"
        assert finding_output.remediation_code_nativeiac == "mock_code_nativeiac"
        assert finding_output.remediation_code_terraform == "mock_code_terraform"
        assert finding_output.remediation_code_cli == "mock_code_cli"
        assert finding_output.remediation_code_other == "mock_code_other"
        assert finding_output.categories == "mock_categories"
        assert finding_output.depends_on == "mock_depends_on"
        assert finding_output.related_to == "mock_related_to"
        assert finding_output.notes == "mock_notes"
        assert finding_output.account_uid == "mock_account_uid"
        assert finding_output.account_name == "context: In-Cluster"
        assert finding_output.account_email == "mock_account_email"
        assert finding_output.account_organization_uid == "mock_account_org_uid"
        assert finding_output.account_organization_name == "mock_account_org_name"
        assert finding_output.account_tags == {"tag1": "value1"}
        assert finding_output.prowler_version == "1.0.0"
        assert finding_output.timestamp == 1622520000
