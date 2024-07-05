import logging

import pytest


@pytest.fixture(autouse=True)
def disable_logging():
    logging.disable(logging.CRITICAL)
