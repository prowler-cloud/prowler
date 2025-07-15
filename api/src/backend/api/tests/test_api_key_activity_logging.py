"""
Tests for API Key Activity Logging functionality.

These tests verify that comprehensive API key usage is logged for:
- Security auditing and incident response
- Compliance requirements
- Usage pattern analysis
- Compromised key detection
"""

import json
from unittest.mock import MagicMock, patch
from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from api.models import APIKey, APIKeyActivity, Tenant
from api.middleware import APILoggingMiddleware
from api.authentication import APIKeyAuthentication

User = get_user_model()


class APIKeyActivityLoggingTest(TestCase):
    """Test comprehensive API key activity logging."""

    def setUp(self):
        self.factory = RequestFactory()
        
        # Create test tenant
        self.tenant = Tenant.objects.create(
            name="Test Tenant",
            email_domain="test.com"
        )
        
        # Create test user
        self.user = User.objects.create(
            email="test@test.com",
            name="Test User",
            company_name="Test Company"
        )
        
        # Create test API key
        self.api_key = APIKey.objects.create(
            name="Test API Key",
            created_by=self.user,
            tenant_id=self.tenant.id,
            key_hash="test_hash",
            prefix="testkey"
        )

    def test_middleware_logs_api_key_requests_with_comprehensive_data(self):
        """Test that the middleware logs API key requests with all required fields."""
        request = self.factory.get("/api/v1/scans?filter=active")
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        request.META['HTTP_USER_AGENT'] = 'ProwlerClient/1.0'
        
        # Mock authentication info
        auth_info = {
            'api_key_id': str(self.api_key.id),
            'api_key_name': self.api_key.name,
            'user_id': str(self.user.id),
            'tenant_id': str(self.tenant.id),
        }
        
        response = MagicMock()
        response.status_code = 200
        response.get.return_value = '1024'  # Content-Length
        
        with patch('api.middleware.extract_auth_info') as mock_extract_auth_info:
            mock_extract_auth_info.return_value = auth_info
            
            with patch('api.middleware.logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                middleware = APILoggingMiddleware(lambda req: response)
                
                with patch('api.middleware.time.time') as mock_time:
                    mock_time.side_effect = [1000.0, 1001.5]  # 1.5 second duration
                    
                    middleware(request)
                    
                    # Verify comprehensive logging data was captured
                    mock_logger.info.assert_called_once()
                    call_args = mock_logger.info.call_args
                    
                    # Check message includes API key information
                    message = call_args[0][0]
                    self.assertIn("API Request: GET /api/v1/scans", message)
                    self.assertIn("[API Key: Test API Key]", message)
                    
                    # Check extra data includes all required fields
                    extra_data = call_args[1]['extra']
                    self.assertEqual(extra_data['api_key_id'], str(self.api_key.id))
                    self.assertEqual(extra_data['api_key_name'], self.api_key.name)
                    self.assertEqual(extra_data['authentication_method'], 'api_key')
                    self.assertTrue(extra_data['is_api_key_request'])
                    self.assertEqual(extra_data['source_ip'], '192.168.1.100')
                    self.assertEqual(extra_data['user_agent'], 'ProwlerClient/1.0')
                    self.assertEqual(extra_data['method'], 'GET')
                    self.assertEqual(extra_data['path'], '/api/v1/scans')
                    self.assertEqual(extra_data['status_code'], 200)
                    self.assertEqual(extra_data['duration'], 1.5)

    def test_middleware_saves_api_key_activity_to_database(self):
        """Test that API key activity is saved to database for persistent audit logging."""
        request = self.factory.post("/api/v1/scans", data=json.dumps({"name": "test"}))
        request.META['REMOTE_ADDR'] = '10.0.0.1'
        request.META['HTTP_USER_AGENT'] = 'curl/7.68.0'
        
        auth_info = {
            'api_key_id': str(self.api_key.id),
            'api_key_name': self.api_key.name,
            'user_id': str(self.user.id),
            'tenant_id': str(self.tenant.id),
        }
        
        response = MagicMock()
        response.status_code = 201
        response.get.return_value = '512'
        
        with patch('api.middleware.extract_auth_info') as mock_extract_auth_info:
            mock_extract_auth_info.return_value = auth_info
            
            middleware = APILoggingMiddleware(lambda req: response)
            
            with patch('api.middleware.time.time') as mock_time:
                mock_time.side_effect = [1000.0, 1000.250]  # 250ms duration
                
                # Ensure no activity records exist initially
                self.assertEqual(APIKeyActivity.objects.count(), 0)
                
                middleware(request)
                
                # Verify activity was saved to database
                self.assertEqual(APIKeyActivity.objects.count(), 1)
                
                activity = APIKeyActivity.objects.first()
                self.assertEqual(activity.api_key, self.api_key)
                self.assertEqual(activity.user, self.user)
                self.assertEqual(activity.tenant_id, self.tenant.id)
                self.assertEqual(activity.method, 'POST')
                self.assertEqual(activity.endpoint, '/api/v1/scans')
                self.assertEqual(activity.source_ip, '10.0.0.1')
                self.assertEqual(activity.user_agent, 'curl/7.68.0')
                self.assertEqual(activity.status_code, 201)
                self.assertEqual(activity.response_size, 512)
                self.assertEqual(activity.duration_ms, 250)
                self.assertEqual(activity.query_params, {})




    def test_middleware_logs_query_parameters_for_audit(self):
        """Test that query parameters are logged for audit purposes."""
        request = self.factory.get("/api/v1/scans?provider=aws&region=us-east-1&limit=100")
        
        auth_info = {
            'api_key_id': str(self.api_key.id),
            'api_key_name': self.api_key.name,
            'user_id': str(self.user.id),
            'tenant_id': str(self.tenant.id),
        }
        
        response = MagicMock()
        response.status_code = 200
        
        with patch('api.middleware.extract_auth_info') as mock_extract_auth_info:
            mock_extract_auth_info.return_value = auth_info
            
            middleware = APILoggingMiddleware(lambda req: response)
            middleware(request)
            
            activity = APIKeyActivity.objects.first()
            expected_params = {
                'provider': 'aws',
                'region': 'us-east-1',
                'limit': '100'
            }
            self.assertEqual(activity.query_params, expected_params)

    def test_middleware_handles_missing_api_key_gracefully(self):
        """Test that middleware handles missing API key objects gracefully."""
        request = self.factory.get("/api/v1/scans")
        
        # Use non-existent API key ID
        auth_info = {
            'api_key_id': 'non-existent-key-id',
            'api_key_name': 'Missing Key',
            'user_id': str(self.user.id),
            'tenant_id': str(self.tenant.id),
        }
        
        response = MagicMock()
        response.status_code = 200
        
        with patch('api.middleware.extract_auth_info') as mock_extract_auth_info:
            mock_extract_auth_info.return_value = auth_info
            
            with patch('api.middleware.logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                middleware = APILoggingMiddleware(lambda req: response)
                middleware(request)
                
                # Verify no activity record was created
                self.assertEqual(APIKeyActivity.objects.count(), 0)
                
                # Verify warning was logged
                warning_calls = [call for call in mock_logger.warning.call_args_list 
                                if 'API Key not found for activity logging' in str(call)]
                self.assertEqual(len(warning_calls), 1)

    def test_middleware_handles_database_errors_gracefully(self):
        """Test that middleware handles database errors gracefully without failing requests."""
        request = self.factory.get("/api/v1/scans")
        
        auth_info = {
            'api_key_id': str(self.api_key.id),
            'api_key_name': self.api_key.name,
            'user_id': str(self.user.id),
            'tenant_id': str(self.tenant.id),
        }
        
        response = MagicMock()
        response.status_code = 200
        
        with patch('api.middleware.extract_auth_info') as mock_extract_auth_info:
            mock_extract_auth_info.return_value = auth_info
            
            with patch('api.models.APIKeyActivity.objects.create') as mock_create:
                mock_create.side_effect = Exception("Database error")
                
                with patch('api.middleware.logging.getLogger') as mock_get_logger:
                    mock_logger = MagicMock()
                    mock_get_logger.return_value = mock_logger
                    
                    middleware = APILoggingMiddleware(lambda req: response)
                    result = middleware(request)
                    
                    # Request should still complete successfully
                    self.assertEqual(result, response)
                    
                    # Error should be logged
                    error_calls = [call for call in mock_logger.error.call_args_list 
                                  if 'Failed to save API key activity' in str(call)]
                    self.assertEqual(len(error_calls), 1)

    def test_jwt_requests_not_logged_as_api_key_activity(self):
        """Test that JWT-authenticated requests are not logged as API key activity."""
        request = self.factory.get("/api/v1/scans")
        
        # JWT authentication (no api_key_id)
        auth_info = {
            'user_id': str(self.user.id),
            'tenant_id': str(self.tenant.id),
        }
        
        response = MagicMock()
        response.status_code = 200
        
        with patch('api.middleware.extract_auth_info') as mock_extract_auth_info:
            mock_extract_auth_info.return_value = auth_info
            
            with patch('api.middleware.logging.getLogger') as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger
                
                middleware = APILoggingMiddleware(lambda req: response)
                middleware(request)
                
                # Verify no API key activity was logged
                self.assertEqual(APIKeyActivity.objects.count(), 0)
                
                # Verify general request was still logged with JWT authentication method
                call_args = mock_logger.info.call_args
                extra_data = call_args[1]['extra']
                self.assertEqual(extra_data['authentication_method'], 'jwt')
                self.assertFalse(extra_data['is_api_key_request'])

    def test_api_key_activity_model_indexes_for_security_queries(self):
        """Test that the APIKeyActivity model supports efficient security queries."""
        # Create multiple activity records
        activities = []
        for i in range(5):
            activity = APIKeyActivity.objects.create(
                api_key=self.api_key,
                user=self.user,
                tenant_id=self.tenant.id,
                method='GET',
                endpoint=f'/api/v1/endpoint{i}',
                source_ip=f'192.168.1.{i+1}',
                status_code=200,
                query_params={},

            )
            activities.append(activity)
        
        # Test queries that would be used for security monitoring
        
        # Query by API key (for key-specific analysis)
        key_activities = APIKeyActivity.objects.filter(api_key=self.api_key).order_by('-timestamp')
        self.assertEqual(len(key_activities), 5)
        
        # Query by user (for user activity analysis)
        user_activities = APIKeyActivity.objects.filter(user=self.user).order_by('-timestamp')
        self.assertEqual(len(user_activities), 5)
        
        # Query by source IP (for IP-based analysis)
        ip_activities = APIKeyActivity.objects.filter(source_ip='192.168.1.1')
        self.assertEqual(len(ip_activities), 1)
        
        # Query by tenant (for tenant-scoped analysis)
        tenant_activities = APIKeyActivity.objects.filter(tenant_id=self.tenant.id).order_by('-timestamp')
        self.assertEqual(len(tenant_activities), 5)
        
        # Query for incident response (combined filters)
        incident_activities = APIKeyActivity.objects.filter(
            tenant_id=self.tenant.id,
            api_key=self.api_key,
            source_ip='192.168.1.2'
        ).order_by('-timestamp')
        self.assertEqual(len(incident_activities), 1)

    def test_api_key_activity_string_representation(self):
        """Test the string representation of APIKeyActivity for debugging."""
        activity = APIKeyActivity.objects.create(
            api_key=self.api_key,
            user=self.user,
            tenant_id=self.tenant.id,
            method='POST',
            endpoint='/api/v1/scans',
            source_ip='10.0.0.1',
            status_code=201,
            query_params={}
        )
        
        str_repr = str(activity)
        self.assertIn("API Key Activity: Test API Key")
        self.assertIn("POST /api/v1/scans")
        self.assertIn("at")  # timestamp should be included 