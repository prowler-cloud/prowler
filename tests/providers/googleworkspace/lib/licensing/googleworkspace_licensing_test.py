from unittest.mock import MagicMock

from googleapiclient.errors import HttpError
from httplib2 import Response as HttpResponse

from prowler.providers.googleworkspace.lib.licensing import (
    CLOUD_IDENTITY_PREMIUM_PRODUCT_ID,
    WORKSPACE_PRODUCT_ID,
    edition_reason_suffix,
    fetch_editions,
)

CUSTOMER_ID = "C04cw8iil"
NO_PREMIUM = {"kind": "licensing#licenseAssignmentList"}
PREMIUM = {"items": [{"skuId": "1010050001", "skuName": "Cloud Identity Premium"}]}


def _licensing_service(workspace_pages, premium_pages=(NO_PREMIUM,)):
    """Build a Licensing API client mock that answers per product, pages in order.

    A page may be an exception; execute() raises it in its turn.
    """
    pages = {
        WORKSPACE_PRODUCT_ID: iter(workspace_pages),
        CLOUD_IDENTITY_PREMIUM_PRODUCT_ID: iter(premium_pages),
    }

    def list_for_product(productId, **_kwargs):
        page = next(pages[productId])
        request = MagicMock()
        if isinstance(page, Exception):
            request.execute.side_effect = page
        else:
            request.execute.return_value = page
        return request

    service = MagicMock()
    service.licenseAssignments.return_value.listForProduct.side_effect = (
        list_for_product
    )
    return service


def _http_error(status):
    return HttpError(HttpResponse({"status": str(status)}), b"")


class TestFetchEditions:
    def test_reads_every_page_and_names_each_sku_once(self):
        service = _licensing_service(
            [
                {
                    "items": [
                        {
                            "skuId": "1010020027",
                            "skuName": "Google Workspace Business Starter",
                        },
                        {
                            "skuId": "1010020027",
                            "skuName": "Google Workspace Business Starter",
                        },
                    ],
                    "nextPageToken": "page-2",
                },
                {"items": [{"skuId": "1010020026"}]},
            ]
        )

        editions = fetch_editions(service, CUSTOMER_ID)

        assert editions == ["Business Starter", "Enterprise Standard"]
        calls = service.licenseAssignments().listForProduct.call_args_list
        assert calls[0].kwargs == {
            "productId": WORKSPACE_PRODUCT_ID,
            "customerId": CUSTOMER_ID,
            "maxResults": 1000,
            "pageToken": None,
        }
        assert calls[1].kwargs["pageToken"] == "page-2"
        assert calls[2].kwargs == {
            "productId": CLOUD_IDENTITY_PREMIUM_PRODUCT_ID,
            "customerId": CUSTOMER_ID,
            "maxResults": 1,
        }

    def test_an_unknown_sku_keeps_the_name_the_api_gives(self):
        service = _licensing_service(
            [{"items": [{"skuId": "9999999999", "skuName": "Google Workspace Future"}]}]
        )

        assert fetch_editions(service, CUSTOMER_ID) == ["Google Workspace Future"]

    def test_an_unknown_sku_without_a_name_keeps_its_id(self):
        service = _licensing_service([{"items": [{"skuId": "9999999999"}]}])

        assert fetch_editions(service, CUSTOMER_ID) == ["9999999999"]

    def test_no_licenses(self):
        assert fetch_editions(_licensing_service([{}]), CUSTOMER_ID) == []

    def test_cloud_identity_premium_counts_as_an_edition(self):
        """A Workspace license next to Cloud Identity Premium gets no edition excuse"""
        service = _licensing_service(
            [{"items": [{"skuId": "1010020027"}]}], premium_pages=[PREMIUM]
        )

        assert fetch_editions(service, CUSTOMER_ID) == [
            "Business Starter",
            "Cloud Identity Premium",
        ]

    def test_a_product_the_customer_never_subscribed_to_is_not_held(self):
        """Google does not document the answer for an unheld product: an error about the product itself means not held"""
        for status in (400, 404):
            service = _licensing_service(
                [{"items": [{"skuId": "1010020027"}]}],
                premium_pages=[_http_error(status)],
            )

            assert fetch_editions(service, CUSTOMER_ID) == ["Business Starter"]

    def test_a_failed_cloud_identity_premium_lookup_means_the_editions_are_unknown(
        self,
    ):
        """Nothing may claim a feature is missing while the entitlement is undecided"""
        for error in (_http_error(500), Exception("backend error")):
            service = _licensing_service(
                [{"items": [{"skuId": "1010020027"}]}], premium_pages=[error]
            )

            assert fetch_editions(service, CUSTOMER_ID) == []

    def test_an_api_error_means_the_editions_are_unknown(self):
        service = _licensing_service([Exception("insufficient scopes")])

        assert fetch_editions(service, CUSTOMER_ID) == []

    def test_an_unexpected_response_means_the_editions_are_unknown(self):
        """A client that is not wired for licensing answers with mocks, never with a page"""
        assert fetch_editions(MagicMock(), CUSTOMER_ID) == []

    def test_no_service(self):
        assert fetch_editions(None, CUSTOMER_ID) == []


class TestEditionReasonSuffix:
    def test_names_the_edition_when_every_licensed_edition_lacks_the_feature(self):
        suffix = edition_reason_suffix(
            ["Business Starter"],
            {"Business Starter", "Business Standard"},
            "Drive data protection rules are not available on the Google Workspace {editions}.",
        )

        assert suffix == (
            " This may be expected because Drive data protection rules are not "
            "available on the Google Workspace Business Starter edition."
        )

    def test_lists_every_licensed_edition(self):
        suffix = edition_reason_suffix(
            ["Business Standard", "Business Starter"],
            {"Business Starter", "Business Standard"},
            "the feature is not available on the {editions}.",
        )

        assert suffix == (
            " This may be expected because the feature is not available on the "
            "Business Standard and Business Starter editions."
        )

    def test_separates_three_editions_with_commas(self):
        suffix = edition_reason_suffix(
            ["Business Plus", "Business Standard", "Business Starter"],
            {"Business Starter", "Business Standard", "Business Plus"},
            "the feature is not available on the {editions}.",
        )

        assert suffix == (
            " This may be expected because the feature is not available on the "
            "Business Plus, Business Standard and Business Starter editions."
        )

    def test_a_supported_edition_in_the_mix_gives_no_excuse(self):
        suffix = edition_reason_suffix(
            ["Business Starter", "Enterprise Standard"],
            {"Business Starter"},
            "unused {editions}",
        )

        assert suffix == ""

    def test_cloud_identity_premium_gives_no_excuse(self):
        suffix = edition_reason_suffix(
            ["Business Starter", "Cloud Identity Premium"],
            {"Business Starter"},
            "unused {editions}",
        )

        assert suffix == ""

    def test_unknown_editions_give_no_excuse(self):
        assert edition_reason_suffix([], {"Business Starter"}, "unused") == ""
        assert edition_reason_suffix(None, {"Business Starter"}, "unused") == ""
        assert edition_reason_suffix(MagicMock(), {"Business Starter"}, "unused") == ""
