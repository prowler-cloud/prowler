from unittest.mock import MagicMock, patch

from tests.providers.gcp.gcp_fixtures import (
    GCP_EU1_LOCATION,
    GCP_PROJECT_ID,
    set_mocked_gcp_provider,
)


class Test_logging_sink_created:
    def test_no_projects(self):
        logging_client = MagicMock()

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), patch(
            "prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created import (
                logging_sink_created,
            )

            logging_client.project_ids = []
            logging_client.sinks = []

            check = logging_sink_created()
            result = check.execute()
            assert len(result) == 0

    def test_no_sinks(self):
        logging_client = MagicMock()

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), patch(
            "prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created import (
                logging_sink_created,
            )

            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.sinks = []

            check = logging_sink_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"There are no logging sinks to export copies of all the log entries in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].resource_name == ""
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_EU1_LOCATION

    def test_sink_all(self):
        logging_client = MagicMock()

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), patch(
            "prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.logging.logging_service import Sink
            from prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created import (
                logging_sink_created,
            )

            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.region = GCP_EU1_LOCATION
            logging_client.sinks = [
                Sink(
                    name="sink1",
                    destination="destination1",
                    filter="all",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = logging_sink_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Sink sink1 is enabled exporting copies of all the log entries in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "sink1"
            assert result[0].resource_name == "sink1"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_EU1_LOCATION

    def test_sink_not_all(self):
        logging_client = MagicMock()

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), patch(
            "prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created.logging_client",
            new=logging_client,
        ):
            from prowler.providers.gcp.services.logging.logging_service import Sink
            from prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created import (
                logging_sink_created,
            )

            logging_client.project_ids = [GCP_PROJECT_ID]
            logging_client.region = GCP_EU1_LOCATION
            logging_client.sinks = [
                Sink(
                    name="sink1",
                    destination="destination1",
                    filter="not all",
                    project_id=GCP_PROJECT_ID,
                )
            ]

            check = logging_sink_created()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Sink sink1 is enabled but not exporting copies of all the log entries in project {GCP_PROJECT_ID}."
            )
            assert result[0].resource_id == "sink1"
            assert result[0].resource_name == "sink1"
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == GCP_EU1_LOCATION

    # multiple sinks test gives unexpected results, need to investigate
    # Name of the check could be improved to reflect the fact that it checks for all sinks
    # Check could be improved by ensuring that the resource configured as Destination exists (extracted from GCP CIS 2.0)
    # Sinks at organization level could be checked as well, because it is possible to create sinks at organization level and not need at project level
    # def test_multiple_sinks(self):
    #     logging_client = MagicMock()

    #     with patch(
    #         "prowler.providers.common.provider.Provider.get_global_provider",
    #         return_value=set_mocked_gcp_provider(),
    #     ), patch(
    #         "prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created.logging_client",
    #         new=logging_client,
    #     ):
    #         from prowler.providers.gcp.services.logging.logging_sink_created.logging_sink_created import (
    #             logging_sink_created,
    #         )
    #         from prowler.providers.gcp.services.logging.logging_service import Sink

    #         logging_client.project_ids = [GCP_PROJECT_ID]
    #         logging_client.region = GCP_EU1_LOCATION
    #         logging_client.sinks = [
    #             Sink(
    #                 name="sink1",
    #                 destination="destination1",
    #                 filter="all",
    #                 project_id=GCP_PROJECT_ID,
    #             ),
    #             Sink(
    #                 name="sink2",
    #                 destination="destination2",
    #                 filter="not all",
    #                 project_id=GCP_PROJECT_ID,
    #             ),
    #         ]

    #         check = logging_sink_created()
    #         result = check.execute()
    #         assert len(result) == 2
    #         assert result[0].status == "PASS"
    #         assert (
    #             result[0].status_extended
    #             == f"Sink sink1 is enabled exporting copies of all the log entries in project {GCP_PROJECT_ID}."
    #         )
    #         assert result[0].resource_id == "sink1"
    #         assert result[0].resource_name == "sink1"
    #         assert result[0].project_id == GCP_PROJECT_ID
    #         assert result[0].location == GCP_EU1_LOCATION

    #         assert result[1].status == "FAIL"
    #         assert (
    #             result[1].status_extended
    #             == f"Sink sink2 is enabled but not exporting copies of all the log entries in project {GCP_PROJECT_ID}."
    #         )
    #         assert result[1].resource_id == "sink2"
    #         assert result[1].resource_name == "sink2"
    #         assert result[1].project_id == GCP_PROJECT_ID
    #         assert result[1].location == GCP_EU1_LOCATION
