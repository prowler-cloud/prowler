# def mock_set_gcp_credentials(*_):
#     return (None, "project")


# def mock_get_project_ids(*_):
#     return ["project"]
# def mock_print_audit_credentials(*_):
#     pass


# @patch.object(GCP_Provider, "__set_credentials__", new=mock_set_gcp_credentials)
#     @patch.object(GCP_Provider, "get_project_ids", new=mock_get_project_ids)
#     @patch.object(Audit_Info, "print_gcp_credentials", new=mock_print_audit_credentials)
#     def test_set_audit_info_gcp(self):
#         provider = "gcp"
#         arguments = {
#             "profile": None,
#             "role": None,
#             "session_duration": None,
#             "external_id": None,
#             "regions": None,
#             "organizations_role": None,
#             "subscriptions": None,
#             # We need to set exactly one auth method
#             "credentials_file": None,
#             "project_ids": ["project"],
#             "config_file": default_config_file_path,
#         }

#         audit_info = set_provider_audit_info(provider, arguments)
#         assert isinstance(audit_info, GCP_Audit_Info)

#     def test_set_provider_output_options_gcp(self):
#         #  Set the cloud provider
#         provider = "gcp"
#         # Set the arguments passed
#         arguments = Namespace()
#         arguments.quiet = True
#         arguments.output_modes = ["csv"]
#         arguments.output_directory = "output_test_directory"
#         arguments.verbose = True
#         arguments.output_filename = "output_test_filename"
#         arguments.only_logs = False
#         arguments.unix_timestamp = False

#         audit_info = self.set_mocked_gcp_audit_info()
#         mutelist_file = ""
#         bulk_checks_metadata = {}
#         output_options = set_provider_output_options(
#             provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
#         )
#         assert isinstance(output_options, Gcp_Output_Options)
#         assert output_options.is_quiet
#         assert output_options.output_modes == ["csv"]
#         assert output_options.output_directory == arguments.output_directory
#         assert output_options.mutelist_file == ""
#         assert output_options.bulk_checks_metadata == {}
#         assert output_options.verbose
#         assert output_options.output_filename == arguments.output_filename

#         # Delete testing directory
#         rmdir(arguments.output_directory)

# from argparse import Namespace
# from prowler.config.config import default_config_file_path
# from prowler.providers.gcp.gcp_provider import GcpProvider


class TestGCPProvider:
    # def test_gcp_provider(self):
    #     arguments = Namespace()

    #     arguments.config_file = default_config_file_path

        # with patch(
        #     "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
        #     return_value=AzureIdentityInfo(),
        # ), patch(
        #     "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
        #     return_value={},
        # ):
        # gcp_provider = GcpProvider(arguments)
