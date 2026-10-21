from unittest.mock import MagicMock

from prowler.providers.googleworkspace.lib.licensing import (
    WORKSPACE_PRODUCT_ID,
    edition_reason_suffix,
    fetch_editions,
)

CUSTOMER_ID = "C04cw8iil"


def _licensing_service(pages):
    """Build a Licensing API client mock that returns the given pages in order."""
    service = MagicMock()
    request = service.licenseAssignments().listForProduct.return_value
    request.execute.side_effect = pages
    return service


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
            "Drive data protection rules are not available on the Google Workspace {editions} edition.",
        )

        assert suffix == (
            " This may be expected because Drive data protection rules are not "
            "available on the Google Workspace Business Starter edition."
        )

    def test_lists_every_licensed_edition(self):
        suffix = edition_reason_suffix(
            ["Business Standard", "Business Starter"],
            {"Business Starter", "Business Standard"},
            "the feature is not available on the {editions} editions.",
        )

        assert suffix == (
            " This may be expected because the feature is not available on the "
            "Business Standard, Business Starter editions."
        )

    def test_a_supported_edition_in_the_mix_gives_no_excuse(self):
        suffix = edition_reason_suffix(
            ["Business Starter", "Enterprise Standard"],
            {"Business Starter"},
            "unused {editions}",
        )

        assert suffix == ""

    def test_unknown_editions_give_no_excuse(self):
        assert edition_reason_suffix([], {"Business Starter"}, "unused") == ""
        assert edition_reason_suffix(None, {"Business Starter"}, "unused") == ""
        assert edition_reason_suffix(MagicMock(), {"Business Starter"}, "unused") == ""
