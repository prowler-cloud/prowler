from typing import List, Optional


class OptionsState:
    def __init__(
        self,
        provider: str,
        list_services: bool,
        list_fixers: bool,
        list_categories: bool,
        list_compliance: bool,
        list_compliance_requirements: List[str],
        list_checks: bool,
        list_checks_json: bool,
        log_level: str,
        log_file: Optional[str],
        only_logs: bool,
        status: List[str],
        output_formats: List[str],
        output_filename: Optional[str],
        output_directory: Optional[str],
        verbose: bool,
        ignore_exit_code_3: bool,
        no_banner: bool,
        unix_timestamp: bool,
        profile: Optional[str],
    ):
        self.provider = provider
        self.list_services = list_services
        self.list_fixers = list_fixers
        self.list_categories = list_categories
        self.list_compliance = list_compliance
        self.list_compliance_requirements = list_compliance_requirements
        self.list_checks = list_checks
        self.list_checks_json = list_checks_json
        self.log_level = log_level
        self.log_file = log_file
        self.only_logs = only_logs
        self.status = status
        self.output_formats = output_formats
        self.output_filename = output_filename
        self.output_directory = output_directory
        self.verbose = verbose
        self.ignore_exit_code_3 = ignore_exit_code_3
        self.no_banner = no_banner
        self.unix_timestamp = unix_timestamp
        self.profile = profile
