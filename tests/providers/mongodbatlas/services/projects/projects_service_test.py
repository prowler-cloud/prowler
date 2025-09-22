from unittest.mock import patch

from prowler.providers.mongodbatlas.services.projects.projects_service import (
    AuditConfig,
    MongoDBAtlasNetworkAccessEntry,
    Project,
    Projects,
    ProjectSettings,
)
from tests.providers.mongodbatlas.mongodbatlas_fixtures import (
    ORG_ID,
    PROJECT_ID,
    PROJECT_NAME,
    set_mocked_mongodbatlas_provider,
)


def mock_projects_list_projects(_):
    return {
        PROJECT_ID: Project(
            id=PROJECT_ID,
            name=PROJECT_NAME,
            org_id=ORG_ID,
            created="2024-01-01T00:00:00Z",
            cluster_count=2,
            network_access_entries=[
                MongoDBAtlasNetworkAccessEntry(
                    cidr_block="192.168.1.0/24",
                    ip_address=None,
                    aws_security_group=None,
                    comment="Private network",
                    delete_after_date=None,
                )
            ],
            project_settings=ProjectSettings(
                collect_specific_statistics=True,
                data_explorer=True,
                data_explorer_gen_ai_features=False,
                data_explorer_gen_ai_sample_documents=False,
                extended_storage_sizes=True,
                performance_advisories=True,
                real_time_performance_panel=True,
                schema_advisor=True,
            ),
            audit_config=AuditConfig(
                enabled=True,
                audit_filter='{"atype": "authenticate", "param": {"user": "admin"}}',
            ),
            location="global",
        )
    }


@patch(
    "prowler.providers.mongodbatlas.services.projects.projects_service.Projects._list_projects",
    new=mock_projects_list_projects,
)
class Test_Projects_Service:
    def test_get_client(self):
        projects_service_client = Projects(set_mocked_mongodbatlas_provider())
        assert projects_service_client.__class__.__name__ == "Projects"

    def test_list_projects(self):
        projects_service_client = Projects(set_mocked_mongodbatlas_provider())
        assert len(projects_service_client.projects) == 1

        project = projects_service_client.projects[PROJECT_ID]

        assert project.id == PROJECT_ID
        assert project.name == PROJECT_NAME
        assert project.org_id == ORG_ID
        assert project.created == "2024-01-01T00:00:00Z"
        assert project.cluster_count == 2
        assert project.location == "global"
        assert len(project.network_access_entries) == 1
        assert project.network_access_entries[0].cidr_block == "192.168.1.0/24"
        assert project.network_access_entries[0].comment == "Private network"
        assert project.project_settings is not None
        assert project.project_settings.collect_specific_statistics is True
        assert project.project_settings.data_explorer is True
        assert project.audit_config is not None
        assert project.audit_config.enabled is True


class Test_Projects_Service_Integration:
    def setup_method(self):
        self.mock_provider = set_mocked_mongodbatlas_provider()

    def test_list_projects_with_real_api_calls(self):
        """Test projects listing with mocked API responses"""
        with patch.object(Projects, "__init__", lambda x, y: None):
            projects_service = Projects(self.mock_provider)
            projects_service.provider = self.mock_provider

            # Mock _paginate_request to return project data
            mock_project_data = [
                {
                    "id": PROJECT_ID,
                    "name": PROJECT_NAME,
                    "orgId": ORG_ID,
                    "created": "2024-01-01T00:00:00Z",
                }
            ]
            with patch.object(
                projects_service, "_paginate_request", return_value=mock_project_data
            ):
                # Mock _get_cluster_count
                with patch.object(
                    projects_service, "_get_cluster_count", return_value=2
                ):
                    # Mock _get_network_access_entries
                    with patch.object(
                        projects_service,
                        "_get_network_access_entries",
                        return_value=[
                            MongoDBAtlasNetworkAccessEntry(
                                cidr_block="192.168.1.0/24", comment="Private network"
                            )
                        ],
                    ):
                        # Mock _get_project_settings
                        with patch.object(
                            projects_service,
                            "_get_project_settings",
                            return_value=ProjectSettings(
                                collect_specific_statistics=True,
                                data_explorer=True,
                                data_explorer_gen_ai_features=False,
                                data_explorer_gen_ai_sample_documents=False,
                                extended_storage_sizes=True,
                                performance_advisories=True,
                                real_time_performance_panel=True,
                                schema_advisor=True,
                            ),
                        ):
                            # Mock _get_audit_config
                            with patch.object(
                                projects_service,
                                "_get_audit_config",
                                return_value=AuditConfig(
                                    enabled=True,
                                    audit_filter='{"atype": "authenticate"}',
                                ),
                            ):
                                projects = projects_service._list_projects()

                                assert len(projects) == 1
                                assert PROJECT_ID in projects

                                project = projects[PROJECT_ID]
                                assert project.name == PROJECT_NAME
                                assert project.org_id == ORG_ID
                                assert project.cluster_count == 2

    def test_list_projects_api_error_handling(self):
        """Test that API errors are handled gracefully"""
        with patch.object(Projects, "__init__", lambda x, y: None):
            projects_service = Projects(self.mock_provider)
            projects_service.provider = self.mock_provider

            # Mock _paginate_request to raise an exception
            with patch.object(
                projects_service,
                "_paginate_request",
                side_effect=Exception("API Error"),
            ):
                with patch(
                    "prowler.providers.mongodbatlas.services.projects.projects_service.logger"
                ) as mock_logger:
                    projects = projects_service._list_projects()

                    # Should be empty due to API error
                    assert len(projects) == 0
                    # Should log error
                    mock_logger.error.assert_called()

    def test_get_cluster_count_error_handling(self):
        """Test that cluster count errors are handled gracefully"""
        with patch.object(Projects, "__init__", lambda x, y: None):
            projects_service = Projects(self.mock_provider)
            projects_service.provider = self.mock_provider

            # Mock _paginate_request to return project data
            mock_project_data = [
                {
                    "id": PROJECT_ID,
                    "name": PROJECT_NAME,
                    "orgId": ORG_ID,
                    "created": "2024-01-01T00:00:00Z",
                }
            ]
            with patch.object(
                projects_service, "_paginate_request", return_value=mock_project_data
            ):
                # Mock _get_cluster_count to raise an exception
                with patch.object(
                    projects_service,
                    "_get_cluster_count",
                    side_effect=Exception("Cluster API Error"),
                ):
                    with patch(
                        "prowler.providers.mongodbatlas.services.projects.projects_service.logger"
                    ) as mock_logger:
                        projects = projects_service._list_projects()

                        # Should be empty due to exception in cluster count
                        assert len(projects) == 0
                        # Should log error
                        mock_logger.error.assert_called()

    def test_get_network_access_entries_error_handling(self):
        """Test that network access entries errors are handled gracefully"""
        with patch.object(Projects, "__init__", lambda x, y: None):
            projects_service = Projects(self.mock_provider)
            projects_service.provider = self.mock_provider

            # Mock _paginate_request to return project data
            mock_project_data = [
                {
                    "id": PROJECT_ID,
                    "name": PROJECT_NAME,
                    "orgId": ORG_ID,
                    "created": "2024-01-01T00:00:00Z",
                }
            ]
            with patch.object(
                projects_service, "_paginate_request", return_value=mock_project_data
            ):
                # Mock _get_cluster_count
                with patch.object(
                    projects_service, "_get_cluster_count", return_value=0
                ):
                    # Mock _get_network_access_entries to raise an exception
                    with patch.object(
                        projects_service,
                        "_get_network_access_entries",
                        side_effect=Exception("Network API Error"),
                    ):
                        with patch(
                            "prowler.providers.mongodbatlas.services.projects.projects_service.logger"
                        ) as mock_logger:
                            projects = projects_service._list_projects()

                            # Should be empty due to exception in network access entries
                            assert len(projects) == 0
                            # Should log error
                            mock_logger.error.assert_called()


class Test_Project_Model:
    def test_project_model_creation(self):
        """Test Project model creation with all fields"""
        network_entries = [
            MongoDBAtlasNetworkAccessEntry(
                cidr_block="192.168.1.0/24", comment="Private network"
            )
        ]

        project_settings = ProjectSettings(
            collect_specific_statistics=True,
            data_explorer=True,
            data_explorer_gen_ai_features=False,
            data_explorer_gen_ai_sample_documents=False,
            extended_storage_sizes=True,
            performance_advisories=True,
            real_time_performance_panel=True,
            schema_advisor=True,
        )

        audit_config = AuditConfig(
            enabled=True, audit_filter='{"atype": "authenticate"}'
        )

        project = Project(
            id=PROJECT_ID,
            name=PROJECT_NAME,
            org_id=ORG_ID,
            created="2024-01-01T00:00:00Z",
            cluster_count=2,
            network_access_entries=network_entries,
            project_settings=project_settings,
            audit_config=audit_config,
            location="global",
        )

        assert project.id == PROJECT_ID
        assert project.name == PROJECT_NAME
        assert project.org_id == ORG_ID
        assert project.created == "2024-01-01T00:00:00Z"
        assert project.cluster_count == 2
        assert project.location == "global"
        assert project.network_access_entries == network_entries
        assert project.project_settings == project_settings
        assert project.audit_config == audit_config

    def test_project_settings_model_creation(self):
        """Test ProjectSettings model creation with all fields"""
        settings = ProjectSettings(
            collect_specific_statistics=True,
            data_explorer=True,
            data_explorer_gen_ai_features=True,
            data_explorer_gen_ai_sample_documents=True,
            extended_storage_sizes=True,
            performance_advisories=True,
            real_time_performance_panel=True,
            schema_advisor=True,
        )

        assert settings.collect_specific_statistics is True
        assert settings.data_explorer is True
        assert settings.data_explorer_gen_ai_features is True
        assert settings.data_explorer_gen_ai_sample_documents is True
        assert settings.extended_storage_sizes is True
        assert settings.performance_advisories is True
        assert settings.real_time_performance_panel is True
        assert settings.schema_advisor is True

    def test_audit_config_model_creation(self):
        """Test AuditConfig model creation with all fields"""
        audit_config = AuditConfig(
            enabled=True,
            audit_filter='{"atype": "authenticate", "param": {"user": "admin"}}',
        )

        assert audit_config.enabled is True
        assert (
            audit_config.audit_filter
            == '{"atype": "authenticate", "param": {"user": "admin"}}'
        )

    def test_network_access_entry_model_creation(self):
        """Test MongoDBAtlasNetworkAccessEntry model creation with all fields"""
        entry = MongoDBAtlasNetworkAccessEntry(
            cidr_block="192.168.1.0/24",
            ip_address="192.168.1.100",
            aws_security_group="sg-12345678",
            comment="Test entry",
            delete_after_date="2024-12-31T23:59:59Z",
        )

        assert entry.cidr_block == "192.168.1.0/24"
        assert entry.ip_address == "192.168.1.100"
        assert entry.aws_security_group == "sg-12345678"
        assert entry.comment == "Test entry"
        assert entry.delete_after_date == "2024-12-31T23:59:59Z"
