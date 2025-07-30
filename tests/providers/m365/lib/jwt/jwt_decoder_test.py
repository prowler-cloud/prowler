import base64
import json
from unittest.mock import patch

from prowler.providers.m365.lib.jwt.jwt_decoder import decode_jwt, decode_msal_token


class TestJwtDecoder:
    def test_decode_jwt_valid_token(self):
        """Test decode_jwt with a valid JWT token"""
        # Create a mock JWT token
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022,
            "roles": ["application_access", "user_read"],
        }

        # Encode header and payload
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        # Create JWT with dummy signature
        token = f"{header_b64}.{payload_b64}.dummy_signature"

        result = decode_jwt(token)

        assert result == payload
        assert result["sub"] == "1234567890"
        assert result["name"] == "John Doe"
        assert result["roles"] == ["application_access", "user_read"]

    def test_decode_jwt_valid_token_with_padding(self):
        """Test decode_jwt with a token that needs base64 padding"""
        # Create mock payload that will need padding
        payload = {"test": "data"}
        payload_json = json.dumps(payload)

        # Encode mock payload without padding
        payload_b64 = (
            base64.urlsafe_b64encode(payload_json.encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        token = f"header.{payload_b64}.signature"

        result = decode_jwt(token)

        assert result == payload

    def test_decode_jwt_invalid_structure_two_parts(self):
        """Test decode_jwt with token that has only 2 parts"""
        token = "header.payload"  # Missing signature

        result = decode_jwt(token)

        assert result == {}

    def test_decode_jwt_invalid_structure_four_parts(self):
        """Test decode_jwt with token that has 4 parts"""
        token = "header.payload.signature.extra"

        result = decode_jwt(token)

        assert result == {}

    def test_decode_jwt_invalid_base64(self):
        """Test decode_jwt with invalid base64 in payload"""
        token = "header.invalid_base64!@#.signature"

        result = decode_jwt(token)

        assert result == {}

    def test_decode_jwt_invalid_json(self):
        """Test decode_jwt with invalid JSON in payload"""
        # Create invalid JSON base64
        invalid_json = "{'invalid': json,}"
        payload_b64 = (
            base64.urlsafe_b64encode(invalid_json.encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        token = f"header.{payload_b64}.signature"

        result = decode_jwt(token)

        assert result == {}

    def test_decode_jwt_empty_token(self):
        """Test decode_jwt with empty token"""
        result = decode_jwt("")
        assert result == {}

    def test_decode_jwt_none_token(self):
        """Test decode_jwt with None token"""
        assert decode_jwt(None) == {}

    @patch("builtins.print")
    def test_decode_jwt_prints_error_on_failure(self, mock_print):
        """Test that decode_jwt prints error message on failure"""
        token = "invalid.token"

        result = decode_jwt(token)

        assert result == {}
        mock_print.assert_called_once()
        assert "Failed to decode the token:" in mock_print.call_args[0][0]

    def test_decode_msal_token_valid_single_line(self):
        """Test decode_msal_token with valid JWT in single line"""
        # Create a valid JWT
        payload = {"roles": ["Exchange.ManageAsApp"], "tenant": "test-tenant"}
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        jwt_token = f"header.{payload_b64}.signature"
        text = f"Some text before {jwt_token} some text after"

        result = decode_msal_token(text)

        assert result == payload
        assert result["roles"] == ["Exchange.ManageAsApp"]

    def test_decode_msal_token_valid_multiline(self):
        """Test decode_msal_token with valid JWT across multiple lines"""
        payload = {"roles": ["application_access"], "user": "test@contoso.com"}
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        jwt_token = f"header.{payload_b64}.signature"
        text = f"""Line 1
        Line 2 with {jwt_token}
        Line 3"""

        result = decode_msal_token(text)

        assert result == payload
        assert result["user"] == "test@contoso.com"

    def test_decode_msal_token_with_whitespace(self):
        """Test decode_msal_token with JWT containing whitespace"""
        payload = {"test": "data"}
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        jwt_token = f"header.{payload_b64}.signature"
        text = f"  Token:   {jwt_token}   "

        result = decode_msal_token(text)

        assert result == payload

    def test_decode_msal_token_no_jwt_found(self):
        """Test decode_msal_token when no JWT pattern is found"""
        text = "This text contains no JWT tokens at all"

        result = decode_msal_token(text)

        assert result == {}

    def test_decode_msal_token_invalid_jwt_pattern(self):
        """Test decode_msal_token with text that looks like JWT but isn't"""
        text = "header.payload"  # Only 2 parts, not valid JWT

        result = decode_msal_token(text)

        assert result == {}

    def test_decode_msal_token_empty_text(self):
        """Test decode_msal_token with empty text"""
        result = decode_msal_token("")
        assert result == {}

    def test_decode_msal_token_none_text(self):
        """Test decode_msal_token with None text"""
        assert decode_msal_token(None) == {}

    @patch("builtins.print")
    def test_decode_msal_token_prints_error_on_failure(self, mock_print):
        """Test that decode_msal_token prints error message on failure"""
        text = "No JWT here"

        result = decode_msal_token(text)

        assert result == {}
        mock_print.assert_called_once()
        assert "Failed to extract and decode the token:" in mock_print.call_args[0][0]

    def test_decode_msal_token_real_world_scenario(self):
        """Test decode_msal_token with a realistic PowerShell output scenario"""
        # Simulate output from Get-MsalToken or similar
        payload = {
            "aud": "https://graph.microsoft.com",
            "iss": "https://sts.windows.net/tenant-id/",
            "iat": 1640995200,
            "exp": 1641081600,
            "roles": ["Application.ReadWrite.All"],
            "sub": "app-subject-id",
        }
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        jwt_token = f"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.{payload_b64}.signature123"

        # Simulate PowerShell output format
        powershell_output = f"""
            AccessToken          : {jwt_token}
            TokenType           : Bearer
            ExpiresOn           : 1/2/2022 12:00:00 AM +00:00
            ExtendedExpiresOn   : 1/2/2022 12:00:00 AM +00:00
        """

        result = decode_msal_token(powershell_output)

        assert result == payload
        assert result["roles"] == ["Application.ReadWrite.All"]
        assert result["aud"] == "https://graph.microsoft.com"

    def test_decode_msal_token_with_jwt_in_json(self):
        """Test decode_msal_token with JWT embedded in JSON-like structure"""
        payload = {"tenant": "test", "scope": "https://graph.microsoft.com/.default"}
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
            .decode("utf-8")
            .rstrip("=")
        )

        jwt_token = f"header.{payload_b64}.signature"

        json_like_text = f'{{"access_token": "{jwt_token}", "token_type": "Bearer"}}'

        result = decode_msal_token(json_like_text)

        assert result == payload
