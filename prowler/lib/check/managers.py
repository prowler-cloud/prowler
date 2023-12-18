import importlib
import os
import sys
import traceback

# To check if client is being GC
import weakref
from types import ModuleType
from typing import Any

from colorama import Fore, Style

from prowler.lib.check.check_to_client_mapper import get_dependencies_for_checks
from prowler.lib.check.custom_checks_metadata import update_check_metadata
from prowler.lib.check.models import Check
from prowler.lib.logger import logger
from prowler.lib.outputs.outputs import report
from prowler.lib.ui.live_display import live_display
from prowler.providers.aws.lib.allowlist.allowlist import allowlist_findings
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.outputs import Provider_Output_Options


class ExecutionManager:
    def __init__(
        self,
        checks_to_execute: list,
        provider: str,
        audit_info: Any,
        audit_output_options: Provider_Output_Options,
        custom_checks_metadata: Any,
    ):
        self.checks_to_execute = checks_to_execute
        self.provider = provider
        self.audit_info = audit_info
        self.audit_output_options = audit_output_options
        self.custom_checks_metadata = custom_checks_metadata

        self.live_display = live_display
        self.live_display.start()
        self.loaded_clients = {}  # defaultdict(lambda: False)
        self.check_dict = self.create_check_service_dict(checks_to_execute)
        self.check_dependencies = get_dependencies_for_checks(provider, self.check_dict)
        self.remaining_checks = self.initialize_remaining_checks(
            self.check_dependencies
        )
        self.services_queue = self.initialize_services_queue(self.check_dependencies)

        self.services_executed = (set(),)
        self.checks_executed = (set(),)

    @staticmethod
    def initialize_remaining_checks(check_dependencies):
        remaining_checks = {}
        for service, checks in check_dependencies.items():
            for check_name, clients in checks.items():
                remaining_checks[(service, check_name)] = clients
        return remaining_checks

    @staticmethod
    def initialize_services_queue(check_dependencies):
        return list(check_dependencies.keys())

    def total_checks_per_service(self):
        """Returns a dictionary with the total number of checks for each service."""
        total_checks = {}
        for service, checks in self.check_dict.items():
            total_checks[service] = len(checks)
        return total_checks

    def find_next_service(self):
        # Prioritize services that use already loaded clients
        for service in self.services_queue:
            checks = self.check_dependencies[service]
            if any(
                client in self.loaded_clients
                for check in checks.values()
                for client in check
            ):
                return service
        return None if not self.services_queue else self.services_queue[0]

    # Imports service clients, and tracks if it needs to be imported
    def import_client(self, client_name):
        if not self.loaded_clients.get(client_name):
            # Dynamically import the client
            module_name, _ = client_name.rsplit("_", 1)
            client_module = importlib.import_module(
                f"prowler.providers.{self.provider}.services.{module_name}.{client_name}"
            )
            self.loaded_clients[client_name] = client_module

    @staticmethod
    def import_check(check_path: str) -> ModuleType:
        """
        Imports an input check using its path

        When importing a module using importlib.import_module, it's loaded and added to the sys.modules cache.
        This means that the module remains in memory and is not garbage collected immediately after use, as it's still referenced in sys.modules.
        This behavior is intentional, as importing modules can be a costly operation, and keeping them in memory allows for faster re-use.
        release_check deletes this reference if it is no longer required by any of the remaining checks
        """
        lib = importlib.import_module(f"{check_path}")
        return lib

    def release_clients(self, completed_check_clients):
        for client_name in completed_check_clients:
            # Determine if any of the remaining checks still require the client
            if not any(
                client == client_name
                for check in self.remaining_checks
                for client in self.remaining_checks[check]
            ):
                # DEBUG: To check GC
                weakref.finalize(
                    self.loaded_clients[client_name], on_finalize, client_name
                )
                # Delete the reference to the client for this object
                del self.loaded_clients[client_name]
                module_name, _ = client_name.rsplit("_", 1)
                # Delete the reference to the client in sys.modules
                del sys.modules[
                    f"prowler.providers.aws.services.{module_name}.{client_name}"
                ]

    def create_finalizer(self, client_name):
        # Just for debugging purposes, will be removed
        def on_finalize():
            self.live_display.print_message(
                f"Client {client_name} is being garbage collected."
            )
            print("gc")

        return on_finalize

    def generate_checks(self):
        """
        This is a generator function, which will:
        * Determine the next service whose checks will be executed
        * Load all the clients which are required by the checks into memory (init them)
        * Yield the service and check name, 1-by-1, to be used within execute_checks
        * Pass the completed checks to release_clients to determine if the clients that were required by the check are no longer needed, and can be garabage collected
        It will complete the checks for a service, before moving onto the next one
        It uses find_next_service to prioritize the next service based on if any of that service's checks require a client that has already been loaded
        """
        while self.remaining_checks:
            current_service = self.find_next_service()
            if not current_service:
                # Execution has completed, return
                break
            # Remove the service from the services_queue
            self.services_queue.remove(current_service)

            if not self.live_display.has_section(current_service):
                total_checks = len(self.check_dict[current_service])
                self.live_display.add_service_section(current_service, total_checks)

            checks = self.check_dependencies[current_service]
            for check_name in checks:
                clients = checks[check_name]
                for client in clients:
                    self.import_client(client)

                yield current_service, check_name

                self.live_display.increment_check_progress()

                del self.remaining_checks[(current_service, check_name)]
                self.release_clients(clients)

    @staticmethod
    def create_check_service_dict(checks_to_execute):
        output = {}
        for check_name in checks_to_execute:
            service = check_name.split("_")[0]
            if service not in output.keys():
                output[service] = []
            output[service].append(check_name)
        return output

    def execute(
        self,
        service: str,
        check_name: str,
        services_executed: set,
        checks_executed: set,
    ):
        # Import check module
        check_module_path = f"prowler.providers.{self.provider}.services.{service}.{check_name}.{check_name}"
        lib = self.import_check(check_module_path)
        # Recover functions from check
        check_to_execute = getattr(lib, check_name)
        c = check_to_execute()

        # Update check metadata to reflect that in the outputs
        if self.custom_checks_metadata and self.custom_checks_metadata["Checks"].get(
            c.CheckID
        ):
            c = update_check_metadata(
                c, self.custom_checks_metadata["Checks"][c.CheckID]
            )

        # Run check
        check_findings = self.run_check(c, self.audit_output_options)

        # Update Audit Status
        services_executed.add(service)
        checks_executed.add(check_name)
        self.audit_info.audit_metadata = self.update_audit_metadata(
            self.audit_info.audit_metadata, services_executed, checks_executed
        )

        # Allowlist findings
        if self.audit_output_options.allowlist_file:
            check_findings = allowlist_findings(
                self.audit_output_options.allowlist_file,
                self.audit_info.audited_account,
                check_findings,
            )

        # Report the check's findings
        report(check_findings, self.audit_output_options, self.audit_info)

        if os.environ.get("PROWLER_REPORT_LIB_PATH"):
            try:
                logger.info("Using custom report interface ...")
                lib = os.environ["PROWLER_REPORT_LIB_PATH"]
                outputs_module = importlib.import_module(lib)
                custom_report_interface = getattr(outputs_module, "report")

                custom_report_interface(
                    check_findings, self.audit_output_options, self.audit_info
                )
            except Exception:
                sys.exit(1)

        return check_findings

    @staticmethod
    def update_audit_metadata(
        audit_metadata: Audit_Metadata, services_executed: set, checks_executed: set
    ) -> Audit_Metadata:
        """update_audit_metadata returns the audit_metadata updated with the new status

        Updates the given audit_metadata using the length of the services_executed and checks_executed
        """
        try:
            audit_metadata.services_scanned = len(services_executed)
            audit_metadata.completed_checks = len(checks_executed)
            audit_metadata.audit_progress = (
                100 * len(checks_executed) / len(audit_metadata.expected_checks)
            )

            return audit_metadata

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def run_check(check: Check, output_options: Provider_Output_Options) -> list:
        findings = []
        if output_options.verbose:
            print(
                f"\nCheck ID: {check.CheckID} - {Fore.MAGENTA}{check.ServiceName}{Fore.YELLOW} [{check.Severity}]{Style.RESET_ALL}"
            )
        logger.debug(f"Executing check: {check.CheckID}")
        try:
            findings = check.execute()
        except Exception as error:
            if not output_options.only_logs:
                print(
                    f"Something went wrong in {check.CheckID}, please use --log-level ERROR"
                )
            logger.error(
                f"{check.CheckID} -- {error.__class__.__name__}[{traceback.extract_tb(error.__traceback__)[-1].lineno}]: {error}"
            )
        finally:
            return findings

    def execute_checks(self) -> list:
        # List to store all the check's findings
        all_findings = []
        # Services and checks executed for the Audit Status
        services_executed = set()
        checks_executed = set()

        # Initialize the Audit Metadata
        self.audit_info.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=self.checks_to_execute,
            completed_checks=0,
            audit_progress=0,
        )

        if os.name != "nt":
            try:
                from resource import RLIMIT_NOFILE, getrlimit

                # Check ulimit for the maximum system open files
                soft, _ = getrlimit(RLIMIT_NOFILE)
                if soft < 4096:
                    logger.warning(
                        f"Your session file descriptors limit ({soft} open files) is below 4096. We recommend to increase it to avoid errors. Solve it running this command `ulimit -n 4096`. For more info visit https://docs.prowler.cloud/en/latest/troubleshooting/"
                    )
            except Exception as error:
                logger.error("Unable to retrieve ulimit default settings")
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        # Execution with the --only-logs flag
        if self.audit_output_options.only_logs:
            for check_name in self.checks_to_execute:
                # Recover service from check name
                service = check_name.split("_")[0]
                try:
                    check_findings = self.execute(
                        service,
                        check_name,
                        self.provider,
                        self.audit_output_options,
                        self.audit_info,
                        services_executed,
                        checks_executed,
                        self.custom_checks_metadata,
                    )
                    all_findings.extend(check_findings)

                # If check does not exists in the provider or is from another provider
                except ModuleNotFoundError:
                    logger.error(
                        f"Check '{check_name}' was not found for the {self.provider.upper()} provider"
                    )
                except Exception as error:
                    logger.error(
                        f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        else:
            # Default execution
            checks_num = len(self.checks_to_execute)
            plural_string = "checks"
            singular_string = "check"

            check_noun = plural_string if checks_num > 1 else singular_string
            print(
                f"{Style.BRIGHT}Executing {checks_num} {check_noun}, please wait...{Style.RESET_ALL}\n"
            )
            total_checks = self.total_checks_per_service()
            completed_checks = {service: 0 for service in total_checks}
            service_findings = []
            for service, check_name in self.generate_checks():
                try:
                    check_findings = self.execute(
                        service,
                        check_name,
                        services_executed,
                        checks_executed,
                    )
                    all_findings.extend(check_findings)
                    service_findings.extend(check_findings)
                    # Update the completed checks count
                    completed_checks[service] += 1

                    # Check if all checks for the service are completed
                    if completed_checks[service] == total_checks[service]:
                        # All checks for the service are completed
                        # Add a summary table or perform other actions
                        live_display.add_summary_table_for_service(service_findings)
                        # Clear service_findings
                        service_findings = []

                # If check does not exists in the provider or is from another provider
                except ModuleNotFoundError:
                    logger.error(
                        f"Check '{check_name}' was not found for the {self.provider.upper()} provider"
                    )
                except Exception as error:
                    logger.error(
                        f"{check_name} - {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        return all_findings


def on_finalize(client_name):
    print(f"Client {client_name} is being garbage collected.")
