from abc import ABC, abstractmethod


class CloudProvider(ABC):
    audit_resources: list = None
    is_quiet: bool
    output_modes: list
    output_directory: str
    allowlist_file: str
    bulk_checks_metadata: dict
    verbose: str
    output_filename: str
    only_logs: bool
    unix_timestamp: bool

    @abstractmethod
    def setup_session(self):
        pass

    @abstractmethod
    def print_credentials(self):
        pass

    # @abstractmethod
    # def create_outputs(self):
    #     pass

    def validate_arguments(self):
        pass


# #AWS
# class AWSProvider(CloudProvider):

#     audited_account: int
#     audited_account_arn: str
#     audited_identity_arn: str
#     audited_user_id: str
#     audited_partition: str
#     profile: str
#     profile_region: str
#     credentials: AWS_Credentials
#     mfa_enabled: bool
#     assumed_role_info: AWS_Assume_Role
#     original_session: session.Session
#     audit_session: session.Session
#     audit_resources: list
#     audit_regions: list
#     organizations_metadata: AWS_Organizations_Info
#     ignore_unused_services: bool = False
#     audit_config: Optional[dict] = None

#     def setup_session(self):
#         #### COMING FROM AWS PROVIDER -> SET ORIGINAL SESSION
#         try:
#             # If we receive a credentials object filled is coming form an assumed role, so renewal is needed
#             if audit_info.credentials:
#                 logger.info("Creating session for assumed role ...")
#                 # From botocore we can use RefreshableCredentials class, which has an attribute (refresh_using)
#                 # that needs to be a method without arguments that retrieves a new set of fresh credentials
#                 # asuming the role again. -> https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L395
#                 assumed_refreshable_credentials = RefreshableCredentials(
#                     access_key=audit_info.credentials.aws_access_key_id,
#                     secret_key=audit_info.credentials.aws_secret_access_key,
#                     token=audit_info.credentials.aws_session_token,
#                     expiry_time=audit_info.credentials.expiration,
#                     refresh_using=self.refresh_credentials,
#                     method="sts-assume-role",
#                 )
#                 # Here we need the botocore session since it needs to use refreshable credentials
#                 assumed_botocore_session = get_session()
#                 assumed_botocore_session._credentials = assumed_refreshable_credentials
#                 assumed_botocore_session.set_config_variable(
#                     "region", audit_info.profile_region
#                 )
#                 return session.Session(
#                     profile_name=audit_info.profile,
#                     botocore_session=assumed_botocore_session,
#                 )
#             # If we do not receive credentials start the session using the profile
#             else:
#                 logger.info("Creating session for not assumed identity ...")
#                 # Input MFA only if a role is not going to be assumed
#                 if audit_info.mfa_enabled and not audit_info.assumed_role_info.role_arn:
#                     mfa_ARN, mfa_TOTP = input_role_mfa_token_and_code()
#                     get_session_token_arguments = {
#                         "SerialNumber": mfa_ARN,
#                         "TokenCode": mfa_TOTP,
#                     }
#                     sts_client = client("sts")
#                     session_credentials = sts_client.get_session_token(
#                         **get_session_token_arguments
#                     )
#                     return session.Session(
#                         aws_access_key_id=session_credentials["Credentials"][
#                             "AccessKeyId"
#                         ],
#                         aws_secret_access_key=session_credentials["Credentials"][
#                             "SecretAccessKey"
#                         ],
#                         aws_session_token=session_credentials["Credentials"][
#                             "SessionToken"
#                         ],
#                         profile_name=audit_info.profile,
#                     )
#                 else:
#                     return session.Session(
#                         profile_name=audit_info.profile,
#                     )
#         except Exception as error:
#             logger.critical(
#                 f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
#             )
#             sys.exit(1)
#         ########
#         # assume role session
#         if input_role:
#             current_audit_info.assumed_role_info.role_arn = input_role
#             current_audit_info.assumed_role_info.session_duration = (
#                 input_session_duration
#             )
#             current_audit_info.assumed_role_info.external_id = input_external_id
#             current_audit_info.assumed_role_info.mfa_enabled = input_mfa

#             # Check if role arn is valid
#             try:
#                 # this returns the arn already parsed into a dict to be used when it is needed to access its fields
#                 role_arn_parsed = parse_iam_credentials_arn(
#                     current_audit_info.assumed_role_info.role_arn
#                 )

#             except Exception as error:
#                 logger.critical(f"{error.__class__.__name__} -- {error}")
#                 sys.exit(1)

#             else:
#                 logger.info(
#                     f"Assuming role {current_audit_info.assumed_role_info.role_arn}"
#                 )
#                 # Assume the role
#                 assumed_role_response = assume_role(
#                     aws_provider.aws_session,
#                     aws_provider.role_info,
#                     sts_endpoint_region,
#                 )
#                 logger.info("Role assumed")
#                 # Set the info needed to create a session with an assumed role
#                 current_audit_info.credentials = AWS_Credentials(
#                     aws_access_key_id=assumed_role_response["Credentials"][
#                         "AccessKeyId"
#                     ],
#                     aws_session_token=assumed_role_response["Credentials"][
#                         "SessionToken"
#                     ],
#                     aws_secret_access_key=assumed_role_response["Credentials"][
#                         "SecretAccessKey"
#                     ],
#                     expiration=assumed_role_response["Credentials"]["Expiration"],
#                 )
#                 # new session is needed
#                 assumed_session = aws_provider.set_session(current_audit_info)

#     def extract_organizations_metadata(self):
#         current_audit_info.assumed_role_info.role_arn = organizations_role_arn
#         current_audit_info.assumed_role_info.session_duration = (
#             input_session_duration
#         )
#         current_audit_info.assumed_role_info.external_id = input_external_id
#         current_audit_info.assumed_role_info.mfa_enabled = input_mfa

#         # Check if role arn is valid
#         try:
#             # this returns the arn already parsed into a dict to be used when it is needed to access its fields
#             role_arn_parsed = parse_iam_credentials_arn(
#                 current_audit_info.assumed_role_info.role_arn
#             )

#         except Exception as error:
#             logger.critical(f"{error.__class__.__name__} -- {error}")
#             sys.exit(1)

#         else:
#             logger.info(
#                 f"Getting organizations metadata for account {organizations_role_arn}"
#             )
#             assumed_credentials = assume_role(
#                 aws_provider.aws_session,
#                 aws_provider.role_info,
#                 sts_endpoint_region,
#             )
#             current_audit_info.organizations_metadata = get_organizations_metadata(
#                 current_audit_info.audited_account, assumed_credentials
#             )
#             logger.info("Organizations metadata retrieved")

#     def

#     def print_credentials(self, audited_regions, profile, assumed_role_info, audited_account, audited_identity_arn, audited_user_id):
#         # Beautify audited regions, set "all" if there is no filter region
#         regions = (
#             ", ".join(audited_regions)
#             if audited_regions is not None
#             else "all"
#         )
#         # Beautify audited profile, set "default" if there is no profile set
#         profile = profile if profile is not None else "default"

#         report = f"""
#     This report is being generated using credentials below:

#     AWS-CLI Profile: {Fore.YELLOW}[{profile}]{Style.RESET_ALL} AWS Filter Region: {Fore.YELLOW}[{regions}]{Style.RESET_ALL}
#     AWS Account: {Fore.YELLOW}[{audited_account}]{Style.RESET_ALL} UserId: {Fore.YELLOW}[{audited_user_id}]{Style.RESET_ALL}
#     Caller Identity ARN: {Fore.YELLOW}[{audited_identity_arn}]{Style.RESET_ALL}
#     """
#         # If -A is set, print Assumed Role ARN
#         if assumed_role_info.role_arn is not None:
#             report += f"""Assumed Role ARN: {Fore.YELLOW}[{assumed_role_info.role_arn}]{Style.RESET_ALL}
# """
