import base64
import json
from datetime import date, datetime
from unittest.mock import MagicMock, patch

import pytest
import requests

from prowler.lib.integrations.elasticsearch.elasticsearch import (
    ELASTICSEARCH_MAX_BATCH,
    Elasticsearch,
    ElasticsearchConnection,
    _json_serial,
)
from prowler.lib.integrations.elasticsearch.exceptions.exceptions import (
    ElasticsearchConnectionError,
    ElasticsearchIndexError,
)

ES_URL = "https://localhost:9200"
ES_INDEX = "prowler-findings"
ES_API_KEY = "test-api-key"
ES_USERNAME = "elastic"
ES_PASSWORD = "changeme"


def _make_finding(status_code="FAIL", uid="finding-1"):
    return {
        "status_code": status_code,
        "finding_info": {"uid": uid, "title": "Test finding"},
        "severity": "HIGH",
    }


class TestJsonSerial:
    def test_datetime_serialization(self):
        dt = datetime(2024, 1, 15, 10, 30, 0)
        assert _json_serial(dt) == "2024-01-15T10:30:00"

    def test_date_serialization(self):
        d = date(2024, 1, 15)
        assert _json_serial(d) == "2024-01-15"

    def test_set_serialization(self):
        s = {1, 2, 3}
        result = _json_serial(s)
        assert isinstance(result, list)
        assert sorted(result) == [1, 2, 3]

    def test_unsupported_type_raises(self):
        with pytest.raises(TypeError, match="not JSON serializable"):
            _json_serial(object())


class TestElasticsearchInit:
    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_init_with_api_key(self, mock_session):
        mock_session.return_value = MagicMock()
        es = Elasticsearch(
            url=ES_URL,
            index=ES_INDEX,
            api_key=ES_API_KEY,
        )
        assert es._url == ES_URL
        assert es._index == ES_INDEX
        assert es._api_key == ES_API_KEY
        assert es._username is None
        assert es._password is None
        assert es._skip_tls_verify is False
        assert es._send_only_fails is False

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_init_with_basic_auth(self, mock_session):
        mock_session.return_value = MagicMock()
        es = Elasticsearch(
            url=ES_URL,
            index=ES_INDEX,
            username=ES_USERNAME,
            password=ES_PASSWORD,
        )
        assert es._username == ES_USERNAME
        assert es._password == ES_PASSWORD
        assert es._api_key is None

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_init_url_trailing_slash_stripped(self, mock_session):
        mock_session.return_value = MagicMock()
        es = Elasticsearch(
            url="https://localhost:9200/",
            index=ES_INDEX,
            api_key=ES_API_KEY,
        )
        assert es._url == "https://localhost:9200"

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_init_empty_findings_default(self, mock_session):
        mock_session.return_value = MagicMock()
        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        assert es._findings == []


class TestFilterFindings:
    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_filter_findings_send_only_fails(self, mock_session):
        mock_session.return_value = MagicMock()
        findings = [
            _make_finding("FAIL", "f1"),
            _make_finding("PASS", "f2"),
            _make_finding("FAIL", "f3"),
        ]
        es = Elasticsearch(
            url=ES_URL,
            index=ES_INDEX,
            api_key=ES_API_KEY,
            findings=findings,
            send_only_fails=True,
        )
        assert len(es._findings) == 2
        assert all(f["status_code"] == "FAIL" for f in es._findings)

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_filter_findings_send_all(self, mock_session):
        mock_session.return_value = MagicMock()
        findings = [
            _make_finding("FAIL", "f1"),
            _make_finding("PASS", "f2"),
        ]
        es = Elasticsearch(
            url=ES_URL,
            index=ES_INDEX,
            api_key=ES_API_KEY,
            findings=findings,
            send_only_fails=False,
        )
        assert len(es._findings) == 2


class TestCreateSession:
    def test_create_session_api_key_auth(self):
        es = Elasticsearch(
            url=ES_URL,
            index=ES_INDEX,
            api_key=ES_API_KEY,
        )
        assert es._session.headers["Authorization"] == f"ApiKey {ES_API_KEY}"
        assert es._session.headers["Content-Type"] == "application/json"
        assert es._session.verify is True

    def test_create_session_basic_auth(self):
        es = Elasticsearch(
            url=ES_URL,
            index=ES_INDEX,
            username=ES_USERNAME,
            password=ES_PASSWORD,
        )
        expected_creds = base64.b64encode(
            f"{ES_USERNAME}:{ES_PASSWORD}".encode()
        ).decode()
        assert es._session.headers["Authorization"] == f"Basic {expected_creds}"

    def test_create_session_skip_tls(self):
        es = Elasticsearch(
            url=ES_URL,
            index=ES_INDEX,
            api_key=ES_API_KEY,
            skip_tls_verify=True,
        )
        assert es._session.verify is False

    def test_create_session_no_auth(self):
        es = Elasticsearch(
            url=ES_URL,
            index=ES_INDEX,
        )
        assert "Authorization" not in es._session.headers


class TestTestConnection:
    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_connection_success(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        result = es.test_connection()

        assert isinstance(result, ElasticsearchConnection)
        assert result.connected is True
        assert result.error_message == ""

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_connection_auth_failure(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_session.get.return_value = mock_response
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key="bad-key")
        result = es.test_connection()

        assert result.connected is False
        assert "Authentication failed" in result.error_message

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_connection_error(self, mock_create_session):
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError(
            "Connection refused"
        )
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        result = es.test_connection()

        assert result.connected is False
        assert "Could not connect" in result.error_message

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_connection_ssl_error(self, mock_create_session):
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.SSLError("SSL error")
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        result = es.test_connection()

        assert result.connected is False
        assert "SSL/TLS error" in result.error_message

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_connection_timeout(self, mock_create_session):
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout("Timed out")
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        result = es.test_connection()

        assert result.connected is False
        assert "timed out" in result.error_message


class TestCreateIndexIfNotExists:
    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_index_already_exists(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.head.return_value = mock_response
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        result = es.create_index_if_not_exists()

        assert result is True
        mock_session.put.assert_not_called()

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_index_created_successfully(self, mock_create_session):
        mock_session = MagicMock()
        # HEAD returns 404 (index doesn't exist)
        head_response = MagicMock()
        head_response.status_code = 404
        mock_session.head.return_value = head_response
        # PUT creates the index
        put_response = MagicMock()
        put_response.status_code = 200
        mock_session.put.return_value = put_response
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        result = es.create_index_if_not_exists()

        assert result is True
        mock_session.put.assert_called_once()

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_index_creation_fails(self, mock_create_session):
        mock_session = MagicMock()
        head_response = MagicMock()
        head_response.status_code = 404
        mock_session.head.return_value = head_response
        put_response = MagicMock()
        put_response.status_code = 400
        put_response.text = "Bad request"
        mock_session.put.return_value = put_response
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        result = es.create_index_if_not_exists()

        assert result is False

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_index_creation_exception(self, mock_create_session):
        mock_session = MagicMock()
        mock_session.head.side_effect = Exception("Network error")
        mock_create_session.return_value = mock_session

        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)

        with pytest.raises(ElasticsearchIndexError):
            es.create_index_if_not_exists()


class TestBatchSendToElasticsearch:
    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_no_findings(self, mock_create_session):
        mock_create_session.return_value = MagicMock()
        es = Elasticsearch(url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY)
        result = es.batch_send_to_elasticsearch()
        assert result == 0

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_send_findings_success(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"errors": False, "items": []}
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        findings = [_make_finding("FAIL", f"f{i}") for i in range(3)]
        es = Elasticsearch(
            url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY, findings=findings
        )
        result = es.batch_send_to_elasticsearch()

        assert result == 3
        mock_session.post.assert_called_once()

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_send_findings_partial_failure(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "errors": True,
            "items": [
                {"index": {"status": 201}},
                {"index": {"status": 400}},
                {"index": {"status": 201}},
            ],
        }
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        findings = [_make_finding("FAIL", f"f{i}") for i in range(3)]
        es = Elasticsearch(
            url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY, findings=findings
        )
        result = es.batch_send_to_elasticsearch()

        assert result == 2

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_send_findings_bulk_request_failure(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        findings = [_make_finding("FAIL", "f1")]
        es = Elasticsearch(
            url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY, findings=findings
        )
        result = es.batch_send_to_elasticsearch()

        assert result == 0

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_send_findings_connection_error(self, mock_create_session):
        mock_session = MagicMock()
        mock_session.post.side_effect = Exception("Connection lost")
        mock_create_session.return_value = mock_session

        findings = [_make_finding("FAIL", "f1")]
        es = Elasticsearch(
            url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY, findings=findings
        )

        with pytest.raises(ElasticsearchConnectionError):
            es.batch_send_to_elasticsearch()


class TestSendFindingsInBatches:
    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_batching_with_more_than_max_batch(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"errors": False, "items": []}
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        # Create more findings than ELASTICSEARCH_MAX_BATCH
        findings = [
            _make_finding("FAIL", f"f{i}") for i in range(ELASTICSEARCH_MAX_BATCH + 10)
        ]
        es = Elasticsearch(
            url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY, findings=findings
        )
        result = es.batch_send_to_elasticsearch()

        # Should have been called twice (one full batch + one partial)
        assert mock_session.post.call_count == 2
        assert result == ELASTICSEARCH_MAX_BATCH + 10

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_finding_without_uid(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"errors": False, "items": []}
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        findings = [{"status_code": "FAIL", "severity": "HIGH"}]
        es = Elasticsearch(
            url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY, findings=findings
        )
        result = es.batch_send_to_elasticsearch()

        assert result == 1
        # Verify the bulk body doesn't include _id
        call_args = mock_session.post.call_args
        body = call_args.kwargs.get("data") or call_args[1].get("data")
        lines = body.strip().split("\n")
        action = json.loads(lines[0])
        assert "_id" not in action["index"]

    @patch(
        "prowler.lib.integrations.elasticsearch.elasticsearch.Elasticsearch._create_session"
    )
    def test_finding_with_datetime_serialization(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"errors": False, "items": []}
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        findings = [
            {
                "status_code": "FAIL",
                "time_dt": datetime(2024, 1, 15, 10, 0, 0),
                "finding_info": {"uid": "f1"},
            }
        ]
        es = Elasticsearch(
            url=ES_URL, index=ES_INDEX, api_key=ES_API_KEY, findings=findings
        )
        result = es.batch_send_to_elasticsearch()

        assert result == 1
        call_args = mock_session.post.call_args
        body = call_args.kwargs.get("data") or call_args[1].get("data")
        lines = body.strip().split("\n")
        doc = json.loads(lines[1])
        assert doc["time_dt"] == "2024-01-15T10:00:00"
