from unittest.mock import MagicMock, patch

import pytest
from django.core.cache import cache
from django.http import HttpResponse, JsonResponse
from django.test import RequestFactory, override_settings
from django.contrib.auth import get_user_model

from api.middleware import APILoggingMiddleware, APIKeyRateLimitMiddleware

User = get_user_model()


@pytest.mark.django_db
@patch("logging.getLogger")
def test_api_logging_middleware_logging(mock_logger):
    factory = RequestFactory()

    request = factory.get("/test-path?param1=value1&param2=value2")
    request.method = "GET"

    response = HttpResponse()
    response.status_code = 200

    get_response = MagicMock(return_value=response)

    with patch("api.middleware.extract_auth_info") as mock_extract_auth_info:
        mock_extract_auth_info.return_value = {
            "user_id": "user123",
            "tenant_id": "tenant456",
        }

        with patch("api.middleware.logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            middleware = APILoggingMiddleware(get_response)

            with patch("api.middleware.time.time") as mock_time:
                mock_time.side_effect = [1000.0, 1001.0]  # Start time and end time

                middleware(request)

                get_response.assert_called_once_with(request)

                mock_extract_auth_info.assert_called_once_with(request)

                expected_extra = {
                    "user_id": "user123",
                    "tenant_id": "tenant456",
                    "method": "GET",
                    "path": "/test-path",
                    "query_params": {"param1": "value1", "param2": "value2"},
                    "status_code": 200,
                    "duration": 1.0,
                }

                mock_logger.info.assert_called_once_with("", extra=expected_extra)


class TestAPIKeyRateLimitMiddleware:
    """Test suite for the API key rate limiting middleware."""

    @pytest.fixture
    def factory(self):
        return RequestFactory()

    @pytest.fixture
    def middleware(self):
        get_response = MagicMock(return_value=HttpResponse(status=200))
        return APIKeyRateLimitMiddleware(get_response)

    @pytest.fixture
    def api_key_request(self, factory):
        """Create a request with API key authentication."""
        request = factory.get("/api/test")
        request.auth = {
            "api_key_id": "test-api-key-123",
            "user_id": "user-456",
            "tenant_id": "tenant-789"
        }
        return request

    @pytest.fixture
    def jwt_request(self, factory):
        """Create a request with JWT authentication (no API key)."""
        request = factory.get("/api/test")
        request.auth = {
            "user_id": "user-456",
            "tenant_id": "tenant-789"
            # No api_key_id
        }
        return request

    @pytest.fixture
    def user_with_unlimited_role(self):
        """Create a user with unlimited visibility role."""
        user = User.objects.create_user(
            email="admin@test.com",
            password="Password123!"
        )
        return user

    def test_rate_limiting_disabled(self, middleware, api_key_request):
        """Test that rate limiting is skipped when disabled."""
        with override_settings(API_RATE_LIMIT_ENABLED=False):
            middleware.enabled = False
            response = middleware(api_key_request)
            assert response.status_code == 200

    def test_non_api_key_request_skipped(self, middleware, jwt_request):
        """Test that non-API key requests are not rate limited."""
        response = middleware(jwt_request)
        assert response.status_code == 200

    def test_no_auth_request_skipped(self, middleware, factory):
        """Test that requests without authentication are not rate limited."""
        request = factory.get("/api/test")
        # No request.auth attribute
        response = middleware(request)
        assert response.status_code == 200

    @patch("api.middleware.get_role")
    def test_admin_bypass(self, mock_get_role, middleware, api_key_request, user_with_unlimited_role):
        """Test that users with unlimited visibility bypass rate limits."""
        # Mock user on request
        api_key_request.user = user_with_unlimited_role
        api_key_request.user.is_authenticated = True
        
        # Mock role with unlimited visibility
        mock_role = MagicMock()
        mock_role.unlimited_visibility = True
        mock_get_role.return_value = mock_role
        
        response = middleware(api_key_request)
        assert response.status_code == 200
        mock_get_role.assert_called_once_with(user_with_unlimited_role)

    @patch("api.middleware.get_role")
    def test_admin_bypass_role_check_exception(self, mock_get_role, middleware, api_key_request, user_with_unlimited_role):
        """Test that role check exceptions don't break the request."""
        api_key_request.user = user_with_unlimited_role
        api_key_request.user.is_authenticated = True
        
        # Mock role check to raise exception
        mock_get_role.side_effect = Exception("Database error")
        
        response = middleware(api_key_request)
        # Should continue with rate limiting since bypass failed
        assert response.status_code == 200

    @override_settings(
        API_RATE_LIMIT_REQUESTS_PER_MINUTE=2,
        API_RATE_LIMIT_REQUESTS_PER_HOUR=10,
        API_RATE_LIMIT_REQUESTS_PER_DAY=100
    )
    def test_rate_limit_enforcement_per_minute(self, middleware, api_key_request):
        """Test rate limit enforcement for per-minute limits."""
        # Clear any existing cache
        cache.clear()
        
        api_key_id = "test-api-key-123"
        
        # First request should pass
        response1 = middleware(api_key_request)
        assert response1.status_code == 200
        
        # Second request should pass
        response2 = middleware(api_key_request)
        assert response2.status_code == 200
        
        # Third request should be rate limited
        response3 = middleware(api_key_request)
        assert response3.status_code == 429
        assert isinstance(response3, JsonResponse)
        
        # Check error response format
        response_data = response3.json()
        assert "errors" in response_data
        assert response_data["errors"][0]["status"] == "429"
        assert response_data["errors"][0]["code"] == "rate_limit_exceeded"
        assert "minute" in response_data["errors"][0]["detail"]

    @override_settings(
        API_RATE_LIMIT_REQUESTS_PER_MINUTE=0,  # Disabled
        API_RATE_LIMIT_REQUESTS_PER_HOUR=1,    # Very low limit
        API_RATE_LIMIT_REQUESTS_PER_DAY=100
    )
    def test_rate_limit_enforcement_per_hour(self, middleware, api_key_request):
        """Test rate limit enforcement for per-hour limits."""
        cache.clear()
        
        # First request should pass
        response1 = middleware(api_key_request)
        assert response1.status_code == 200
        
        # Second request should be rate limited
        response2 = middleware(api_key_request)
        assert response2.status_code == 429
        
        response_data = response2.json()
        assert "hour" in response_data["errors"][0]["detail"]

    @override_settings(
        API_RATE_LIMIT_REQUESTS_PER_MINUTE=0,  # Disabled
        API_RATE_LIMIT_REQUESTS_PER_HOUR=0,    # Disabled
        API_RATE_LIMIT_REQUESTS_PER_DAY=1      # Very low limit
    )
    def test_rate_limit_enforcement_per_day(self, middleware, api_key_request):
        """Test rate limit enforcement for per-day limits."""
        cache.clear()
        
        # First request should pass
        response1 = middleware(api_key_request)
        assert response1.status_code == 200
        
        # Second request should be rate limited
        response2 = middleware(api_key_request)
        assert response2.status_code == 429
        
        response_data = response2.json()
        assert "day" in response_data["errors"][0]["detail"]

    def test_rate_limit_response_headers(self, middleware, api_key_request):
        """Test that rate limit responses include proper headers."""
        cache.clear()
        
        with override_settings(API_RATE_LIMIT_REQUESTS_PER_MINUTE=1):
            # First request passes
            middleware(api_key_request)
            
            # Second request is rate limited
            response = middleware(api_key_request)
            assert response.status_code == 429
            
            # Check headers
            assert 'Retry-After' in response
            assert 'X-RateLimit-Limit' in response
            assert 'X-RateLimit-Window' in response
            assert 'X-RateLimit-Retry-After' in response
            
            assert response['X-RateLimit-Limit'] == '1'
            assert response['X-RateLimit-Window'] == 'minute'

    def test_only_successful_requests_counted(self, middleware):
        """Test that only successful requests (2xx) are counted toward rate limits."""
        cache.clear()
        
        factory = RequestFactory()
        request = factory.get("/api/test")
        request.auth = {"api_key_id": "test-key"}
        
        # Mock get_response to return different status codes
        def mock_response_500():
            return HttpResponse(status=500)
        
        def mock_response_200():
            return HttpResponse(status=200)
        
        middleware.get_response = mock_response_500
        
        with override_settings(API_RATE_LIMIT_REQUESTS_PER_MINUTE=1):
            # Error responses shouldn't count
            response1 = middleware(request)
            assert response1.status_code == 500
            
            response2 = middleware(request)
            assert response2.status_code == 500
            
            # Now switch to successful responses
            middleware.get_response = mock_response_200
            
            # This should be the first counted request
            response3 = middleware(request)
            assert response3.status_code == 200
            
            # This should hit the rate limit
            response4 = middleware(request)
            assert response4.status_code == 429

    def test_different_api_keys_separate_limits(self, middleware, factory):
        """Test that different API keys have separate rate limits."""
        cache.clear()
        
        request1 = factory.get("/api/test")
        request1.auth = {"api_key_id": "api-key-1"}
        
        request2 = factory.get("/api/test")
        request2.auth = {"api_key_id": "api-key-2"}
        
        with override_settings(API_RATE_LIMIT_REQUESTS_PER_MINUTE=1):
            # First API key hits limit
            response1 = middleware(request1)
            assert response1.status_code == 200
            
            response2 = middleware(request1)  # Same key
            assert response2.status_code == 429
            
            # Second API key should still work
            response3 = middleware(request2)  # Different key
            assert response3.status_code == 200

    @patch("api.middleware.cache")
    def test_cache_error_handling(self, mock_cache, middleware, api_key_request):
        """Test that cache errors don't break the request flow."""
        # Mock cache to raise an exception
        mock_cache.get.side_effect = Exception("Cache connection error")
        mock_cache.set.side_effect = Exception("Cache connection error")
        
        # Request should still proceed despite cache errors
        response = middleware(api_key_request)
        assert response.status_code == 200

    def test_cache_key_generation(self, middleware):
        """Test that cache keys are generated correctly."""
        from django.utils import timezone
        
        api_key_id = "test-key-123"
        now = timezone.now()
        
        # Test minute window
        cache_key = middleware._get_cache_key(api_key_id, "minute", now, 60)
        expected_bucket = int(now.timestamp()) // 60
        expected_key = f"api_rate_limit:{api_key_id}:minute:{expected_bucket}"
        assert cache_key == expected_key
        
        # Test hour window
        cache_key = middleware._get_cache_key(api_key_id, "hour", now, 3600)
        expected_bucket = int(now.timestamp()) // 3600
        expected_key = f"api_rate_limit:{api_key_id}:hour:{expected_bucket}"
        assert cache_key == expected_key
