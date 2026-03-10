from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_compute_image_not_publicly_shared:
    def test_compute_no_images(self):
        compute_client = mock.MagicMock()
        compute_client.images = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_image_not_publicly_shared.compute_image_not_publicly_shared.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_image_not_publicly_shared.compute_image_not_publicly_shared import (
                compute_image_not_publicly_shared,
            )

            check = compute_image_not_publicly_shared()
            result = check.execute()
            assert len(result) == 0

    def test_image_not_publicly_shared(self):
        compute_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_image_not_publicly_shared.compute_image_not_publicly_shared.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_image_not_publicly_shared.compute_image_not_publicly_shared import (
                compute_image_not_publicly_shared,
            )
            from prowler.providers.gcp.services.compute.compute_service import Image

            image = Image(
                name="private-image",
                id="1234567890",
                project_id=GCP_PROJECT_ID,
                publicly_shared=False,
            )

            compute_client.project_ids = [GCP_PROJECT_ID]
            compute_client.images = [image]

            check = compute_image_not_publicly_shared()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Compute Engine disk image private-image is not publicly shared."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "private-image"
            assert result[0].location == "global"

    def test_image_publicly_shared_with_all_authenticated_users(self):
        from prowler.providers.gcp.services.compute.compute_service import Image

        image = Image(
            name="public-image",
            id="1234567890",
            project_id=GCP_PROJECT_ID,
            publicly_shared=True,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.images = [image]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_image_not_publicly_shared.compute_image_not_publicly_shared.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_image_not_publicly_shared.compute_image_not_publicly_shared import (
                compute_image_not_publicly_shared,
            )

            check = compute_image_not_publicly_shared()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Compute Engine disk image public-image is publicly shared with allAuthenticatedUsers."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].resource_name == "public-image"
            assert result[0].location == "global"

    def test_multiple_images_mixed_sharing(self):
        from prowler.providers.gcp.services.compute.compute_service import Image

        private_image = Image(
            name="private-image",
            id="1111111111",
            project_id=GCP_PROJECT_ID,
            publicly_shared=False,
        )

        public_image = Image(
            name="public-image",
            id="2222222222",
            project_id=GCP_PROJECT_ID,
            publicly_shared=True,
        )

        compute_client = mock.MagicMock()
        compute_client.project_ids = [GCP_PROJECT_ID]
        compute_client.images = [private_image, public_image]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.compute.compute_image_not_publicly_shared.compute_image_not_publicly_shared.compute_client",
                new=compute_client,
            ),
        ):
            from prowler.providers.gcp.services.compute.compute_image_not_publicly_shared.compute_image_not_publicly_shared import (
                compute_image_not_publicly_shared,
            )

            check = compute_image_not_publicly_shared()
            result = check.execute()

            assert len(result) == 2

            private_result = next(
                r for r in result if r.resource_name == "private-image"
            )
            public_result = next(r for r in result if r.resource_name == "public-image")

            assert private_result.status == "PASS"
            assert (
                private_result.status_extended
                == "Compute Engine disk image private-image is not publicly shared."
            )

            assert public_result.status == "FAIL"
            assert (
                public_result.status_extended
                == "Compute Engine disk image public-image is publicly shared with allAuthenticatedUsers."
            )
