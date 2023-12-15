import importlib
import sys

# To check if client is being GC
import weakref
from collections import defaultdict

from prowler.lib.ui.live_display import live_display
from prowler.lib.utils.check_to_client_mapper import get_dependencies_for_checks


class ExecutionManager:
    def __init__(self, provider, checks_to_execute):
        self.live_display = live_display
        self.live_display.start()
        self.provider = provider
        self.loaded_clients = defaultdict(int)
        self.check_dict = self.create_check_service_dict(checks_to_execute)
        self.check_dependencies = get_dependencies_for_checks(provider, self.check_dict)
        self.remaining_checks = self.initialize_remaining_checks(
            self.check_dependencies
        )
        self.services_queue = self.initialize_services_queue(self.check_dependencies)

    def initialize_remaining_checks(self, check_dependencies):
        remaining_checks = {}
        for service, checks in check_dependencies.items():
            for check_name, clients in checks.items():
                remaining_checks[(service, check_name)] = clients
        return remaining_checks

    def initialize_services_queue(self, check_dependencies):
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
                client in self.loaded_clients and self.loaded_clients[client] > 0
                for check in checks.values()
                for client in check
            ):
                return service
        return None if not self.services_queue else self.services_queue[0]

    def import_client(self, client_name):
        if self.loaded_clients[client_name] == 0:
            # Dynamically import the client
            module_name, _ = client_name.rsplit("_", 1)
            client_module = importlib.import_module(
                f"prowler.providers.{self.provider}.services.{module_name}.{client_name}"
            )
            setattr(self, client_name, client_module)
        self.loaded_clients[client_name] += 1

    def release_clients(self, completed_check_clients):
        for client_name in completed_check_clients:
            self.loaded_clients[client_name] -= 1
            if self.loaded_clients[client_name] == 0 and not any(
                client
                for check in self.remaining_checks
                for client in self.remaining_checks[check]
            ):
                del self.loaded_clients[client_name]
                module_name, _ = client_name.rsplit("_", 1)
                del sys.modules[
                    f"prowler.providers.aws.services.{module_name}.{client_name}"
                ]
                # To check GC
                weakref.finalize(getattr(self, client_name), on_finalize, client_name)
                delattr(self, client_name)

    def create_finalizer(self, client_name):
        def on_finalize():
            self.live_display.print_message(
                f"Client {client_name} is being garbage collected."
            )
            print("gc")

        return on_finalize

    def execute_checks(self):
        while self.remaining_checks:
            next_service = self.find_next_service()
            if not next_service:
                break

            if not self.live_display.has_section(next_service):
                total_checks = len(self.check_dict[next_service])
                self.live_display.add_service_section(next_service, total_checks)

            self.services_queue.remove(next_service)
            checks = self.check_dependencies[next_service]
            for check_name in checks:
                clients = checks[check_name]
                for client in clients:
                    self.import_client(client)

                yield next_service, check_name

                self.live_display.increment_check_progress()

                self.release_clients(clients)
                del self.remaining_checks[(next_service, check_name)]

    @staticmethod
    def create_check_service_dict(checks_to_execute):
        output = {}
        for check_name in checks_to_execute:
            service = check_name.split("_")[0]
            if service not in output.keys():
                output[service] = []
            output[service].append(check_name)
        return output


def on_finalize(client_name):
    print(f"Client {client_name} is being garbage collected.")
