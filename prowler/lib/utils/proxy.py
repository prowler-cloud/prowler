import gc
from typing import List, Set, Dict


class ClientProxy:
    """
    A ClientsProxy class that allows transparently accessing a target object.

    A proxy class is a way to access an object without actually creating an instance of it.
    The object will be created only when it is needed. This is: when the attribute or method is accessed for the first time.

    Usage example:

    Instead of:

    >>> my_class = MyClass(arg1, arg2)
    >>> my_class.method()

    You can use:

    >>> from prowler.lib.utils.proxy import ClientProxy
    >>> proxied_class = ClientProxy(MyClass, arg1, arg2)

    Now you can call the method as if it was a method of the proxied class:

    >>> proxied_class.method()
    """

    def __init__(self, cls, *args, **kwargs):
        self._cls = cls
        self._args = args
        self._kwargs = kwargs
        self._instance = None

        # Track the client instance
        alive_clients.clients[cls.__name__.lower()] = self

    def _get_instance(self):
        if self._instance is None:
            self._instance = self._cls(*self._args, **self._kwargs)

        return self._instance

    def __getattr__(self, name):
        # Esto se llama cuando se accede a un atributo que no existe en el proxy
        # Delega la llamada al objeto real
        instance = self._get_instance()
        return getattr(instance, name)

    def __setattr__(self, name, value):
        if name in ['_cls', '_args', '_kwargs', '_instance']:
            # Para estos atributos especiales del proxy, usa el comportamiento por defecto
            super().__setattr__(name, value)
        else:
            # Delega la asignación al objeto real
            instance = self._get_instance()
            setattr(instance, name, value)

    def __call__(self, *args, **kwargs):
        instance = self._get_instance()
        return instance(*args, **kwargs)

    def clean_up(self):
        self._instance = None
        gc.collect()


class _AliveClients:
    """
    This module defines a class `_AliveClients` responsible for managing alive cloud clients.

    The idea behind this class is to keep track of the clients that are currently alive and to clean them up when they are no longer needed.

    Usage example:

    >>> from prowler.lib.utils.proxy import alive_clients
    >>> proxied_class = ClientProxy(MyClass, arg1, arg2)
    >>> alive_clients.clean_up(proxied_class)
    """

    def __init__(self):
        self.clients: Dict[str: ClientProxy] = {}
        self._cache = {}

    def clean_up(self, service: str, pending_checks: List[str], checks_to_execute: Set[str]):
        """
        Cleans up the clients associated with a service by executing certain checks.

        Args:
            service (str): The name of the service.
            pending_checks (List[str]): The list of pending checks associated with the service.
        """
        # Calculate the number of checks associated with the service
        cleaned_pending_checks = self._calculate_and_cache_checks(service, pending_checks, "pending")

        # Calculate the number of checks to execute
        cleaned_checks_to_execute = len([x for x in checks_to_execute if x.startswith(service)])

        # Check if the number of checks to execute is equal to the number of checks associated with the service
        if cleaned_pending_checks == cleaned_checks_to_execute:
            self.clients[service].clean_up()
            self._clean_check_cache(service, "pending")

    def _calculate_and_cache_checks(self, service: str, checks: Set[str] | List[str], name: str) -> int:
        """
        Calculates and caches the number of checks associated with a service.

        This method assumes that a check is used only once per service.

        Args:
            service (str): The name of the service.
            checks (Set[str] | List[str]): The list of checks associated with the service.
            name (str): The name of the cache to use.

        Returns:
            int: The number of checks associated with the service.
        """
        key = f"{service}_{name}"

        try:
            return self._cache[key]
        except KeyError:
            result = len([x for x in checks if x.startswith(service)])
            self._cache[key] = result
            return result

    def _clean_check_cache(self, service: str, name: str):
        """
        Cleans the cache for a specific service.

        Args:
            service (str): The name of the service.
            name (str): The name of the cache to clean.
        """
        key = f"{service}_{name}"

        try:
            del self._cache[key]
        except KeyError:
            pass


alive_clients = _AliveClients()
