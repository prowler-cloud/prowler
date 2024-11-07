from datetime import datetime

IMMUTABLE_HASHABLE_TYPES = (str, int, float, bool, tuple, frozenset, bytes, datetime)


__all__ = ("IMMUTABLE_HASHABLE_TYPES",)
