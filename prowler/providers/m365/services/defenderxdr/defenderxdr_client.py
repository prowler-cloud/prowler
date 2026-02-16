"""
DefenderXDR client singleton for Prowler checks.

This module provides a singleton client instance for the DefenderXDR service.
"""

from prowler.providers.common.provider import Provider
from prowler.providers.m365.services.defenderxdr.defenderxdr_service import DefenderXDR

defenderxdr_client = DefenderXDR(Provider.get_global_provider())
