from unittest import mock

# Mock the global provider BEFORE importing the check to prevent the 'session' AttributeError
mock_provider = mock.MagicMock()
mock_provider.session = mock.MagicMock()

with mock.patch("prowler.providers.common.provider.Provider.get_global_provider", return_value=mock_provider):
    from prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled import (
        dns_policy_logging_enabled,
    )

class Test_dns_policy_logging_enabled:
    
    @mock.patch("prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled.compute_client")
    @mock.patch("prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled.dns_client")
    def test_no_networks(self, dns_client_mock, compute_client_mock):
        compute_client_mock.project_ids = ["test-project"]
        compute_client_mock.networks = []
        dns_client_mock.policies = []

        check = dns_policy_logging_enabled()
        result = check.execute()
        
        assert len(result) == 0

    @mock.patch("prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled.compute_client")
    @mock.patch("prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled.dns_client")
    def test_network_without_policy(self, dns_client_mock, compute_client_mock):
        compute_client_mock.project_ids = ["test-project"]
        
        network_mock = mock.MagicMock()
        network_mock.name = "test-vpc-bad"
        network_mock.id = "123456"
        compute_client_mock.networks = [network_mock]

        dns_client_mock.policies = []

        check = dns_policy_logging_enabled()
        result = check.execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "test-vpc-bad"
        assert result[0].resource_name == "test-vpc-bad"
        assert result[0].project_id == "test-project"
        assert result[0].status_extended == "VPC Network test-vpc-bad does NOT have Cloud DNS logging enabled."

    @mock.patch("prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled.compute_client")
    @mock.patch("prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled.dns_client")
    def test_network_with_policy_logging_disabled(self, dns_client_mock, compute_client_mock):
        compute_client_mock.project_ids = ["test-project"]
        
        network_mock = mock.MagicMock()
        network_mock.name = "test-vpc-bad"
        network_mock.id = "123456"
        compute_client_mock.networks = [network_mock]

        policy_mock = mock.MagicMock()
        policy_mock.name = "bad-policy"
        policy_mock.networks = ["/networks/test-vpc-bad"]
        policy_mock.logging = False
        dns_client_mock.policies = [policy_mock]

        check = dns_policy_logging_enabled()
        result = check.execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "test-vpc-bad"
        assert result[0].status_extended == "VPC Network test-vpc-bad does NOT have Cloud DNS logging enabled."

    @mock.patch("prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled.compute_client")
    @mock.patch("prowler.providers.gcp.services.dns.dns_policy_logging_enabled.dns_policy_logging_enabled.dns_client")
    def test_network_with_policy_logging_enabled(self, dns_client_mock, compute_client_mock):
        compute_client_mock.project_ids = ["test-project"]
        
        network_mock = mock.MagicMock()
        network_mock.name = "test-vpc-good"
        network_mock.id = "654321"
        compute_client_mock.networks = [network_mock]

        policy_mock = mock.MagicMock()
        policy_mock.name = "good-policy"
        policy_mock.networks = ["/networks/test-vpc-good"]
        policy_mock.logging = True
        dns_client_mock.policies = [policy_mock]

        check = dns_policy_logging_enabled()
        result = check.execute()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "test-vpc-good"
        assert result[0].status_extended == "VPC Network test-vpc-good has Cloud DNS logging enabled via policy good-policy."