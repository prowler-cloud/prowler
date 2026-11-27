from datetime import datetime, timezone
from unittest import mock

from prowler.providers.vercel.services.domain.domain_service import (
    Domain,
    VercelSSLCertificate,
)
from tests.providers.vercel.vercel_fixtures import (
    DOMAIN_NAME,
    set_mocked_vercel_provider,
)

CERT = {
    "uid": "cert_abc123",
    "cns": [DOMAIN_NAME, f"www.{DOMAIN_NAME}"],
    "created": "2025-06-15T00:00:00.000Z",
    "expiration": "2027-06-15T00:00:00.000Z",
    "autoRenew": True,
}
DOMAIN = {
    "name": DOMAIN_NAME,
    "id": "dom_test",
    "apexName": DOMAIN_NAME,
    "verified": True,
    "configured": True,
}


def _make_domain_service(certs, domains=None, paginate_side_effect=None):
    """Build a Domain service with mocked Vercel API responses.

    Args:
        certs: List of raw cert payloads returned for GET /v4/certs, or an
            exception to raise from that call.
        domains: Raw domain payloads returned for GET /v5/domains.
        paginate_side_effect: Optional side-effect function for _paginate.
    """
    provider = set_mocked_vercel_provider()

    def paginate(path, key, params=None):
        if paginate_side_effect is not None:
            return paginate_side_effect(path, key, params)
        if path == "/v5/domains":
            return domains if domains is not None else [DOMAIN]
        if path == "/v4/certs":
            if isinstance(certs, Exception):
                raise certs
            return certs
        raise AssertionError(f"unexpected _paginate path: {path}")

    def get(path, params=None):
        # The per-domain /v8/certs/{domain} endpoint 404s for Vercel-issued
        # certificates (prowler #13392); the fix must never call it.
        assert not path.startswith("/v8/certs/"), f"stale endpoint called: {path}"
        if path.startswith("/v4/domains/"):
            return {"records": []}
        raise AssertionError(f"unexpected _get path: {path}")

    with (
        mock.patch.object(Domain, "_paginate", side_effect=paginate),
        mock.patch.object(Domain, "_get", side_effect=get),
    ):
        return Domain(provider)


class TestDomainSSLCertificateLookup:
    def test_cert_found_via_certs_list(self):
        """Regression test for #13392: a cert listed by GET /v4/certs whose
        cns cover the domain is attached, even though GET /v8/certs/{domain}
        404s for Vercel-issued certificates."""
        service = _make_domain_service([CERT])
        domain = service.domains[DOMAIN_NAME]
        assert domain.ssl_certificate is not None
        assert domain.ssl_certificate.id == "cert_abc123"
        assert domain.ssl_certificate.cns == [DOMAIN_NAME, f"www.{DOMAIN_NAME}"]
        assert domain.ssl_certificate.auto_renew is True
        assert domain.ssl_certificate.expires_at == datetime(
            2027, 6, 15, tzinfo=timezone.utc
        )
        assert domain.ssl_certificate.created_at == datetime(
            2025, 6, 15, tzinfo=timezone.utc
        )

    def test_cert_matches_wildcard_cn(self):
        wildcard_cert = {
            "uid": "cert_wild",
            "cns": [f"*.{DOMAIN_NAME}"],
            "created": "2025-06-15T00:00:00.000Z",
            "expiration": "2027-06-15T00:00:00.000Z",
            "autoRenew": True,
        }
        app_domain = dict(DOMAIN, name=f"app.{DOMAIN_NAME}", id="dom_app")
        deep_domain = dict(DOMAIN, name=f"deep.app.{DOMAIN_NAME}", id="dom_deep")
        service = _make_domain_service(
            [wildcard_cert], domains=[app_domain, deep_domain]
        )
        assert service.domains[f"app.{DOMAIN_NAME}"].ssl_certificate is not None
        assert service.domains[f"app.{DOMAIN_NAME}"].ssl_certificate.id == "cert_wild"
        # Single-level wildcard must not cover a deeper subdomain.
        assert service.domains[f"deep.app.{DOMAIN_NAME}"].ssl_certificate is None

    def test_no_matching_cert_leaves_ssl_certificate_unset(self):
        other_cert = dict(CERT, uid="cert_other", cns=["other.com"])
        service = _make_domain_service([other_cert])
        assert service.domains[DOMAIN_NAME].ssl_certificate is None

    def test_expired_cert_is_attached_with_past_expiry(self):
        """Regression test for the CodeRabbit review on #13546: the
        ``/v4/certs`` list response carries ``expiration`` as an ISO 8601
        string, not ``expiresAt`` epoch milliseconds. An expired
        certificate must be attached with a past ``expires_at`` so the
        ``domain_ssl_certificate_valid`` check FAILs it, instead of getting
        ``expires_at=None`` and passing through the missing-expiry branch."""
        expired_cert = dict(
            CERT, uid="cert_expired", expiration="2020-01-01T00:00:00.000Z"
        )
        service = _make_domain_service([expired_cert])
        domain = service.domains[DOMAIN_NAME]
        assert domain.ssl_certificate is not None
        assert domain.ssl_certificate.id == "cert_expired"
        assert domain.ssl_certificate.expires_at is not None
        assert domain.ssl_certificate.expires_at < datetime.now(timezone.utc)

    def test_empty_certs_list_leaves_ssl_certificate_unset(self):
        service = _make_domain_service([])
        assert service.domains[DOMAIN_NAME].ssl_certificate is None

    def test_latest_expiry_wins_when_several_certs_cover_domain(self):
        old_cert = dict(CERT, uid="cert_old", expiration="2028-01-01T00:00:00.000Z")
        new_cert = dict(CERT, uid="cert_new", expiration="2029-01-01T00:00:00.000Z")
        service = _make_domain_service([old_cert, new_cert])
        assert service.domains[DOMAIN_NAME].ssl_certificate.id == "cert_new"

    def test_certs_list_failure_leaves_ssl_certificate_unset(self):
        service = _make_domain_service(Exception("boom"))
        assert service.domains[DOMAIN_NAME].ssl_certificate is None

    def test_cert_covers_domain(self):
        cert = VercelSSLCertificate(id="cert_1", cns=[DOMAIN_NAME])
        assert Domain._cert_covers_domain(cert, DOMAIN_NAME) is True
        assert Domain._cert_covers_domain(cert, f"other.{DOMAIN_NAME}") is False

        wildcard = VercelSSLCertificate(id="cert_2", cns=[f"*.{DOMAIN_NAME}"])
        assert Domain._cert_covers_domain(wildcard, f"app.{DOMAIN_NAME}") is True
        assert Domain._cert_covers_domain(wildcard, f"deep.app.{DOMAIN_NAME}") is False
        assert Domain._cert_covers_domain(wildcard, DOMAIN_NAME) is False
