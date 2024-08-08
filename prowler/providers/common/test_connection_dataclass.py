from dataclasses import dataclass
from typing import Any


@dataclass
class TestConnection:
    connected: bool = False
    error: Exception = None
    result: Any = None
