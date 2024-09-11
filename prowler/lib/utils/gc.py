import gc
from contextlib import contextmanager


# TODO: we'll need to do a further review of this once we address the outputs generation with S3
@contextmanager
def force_gc(disable_gc=False):
    """
    Context manager that temporarily disables garbage collection if `disable_gc` argument is True.

    Args:
        disable_gc (bool): If True, garbage collection will be disabled temporarily.

    Yields:
        None

    Notes:
        - If `disable_gc` is True, garbage collection will be disabled before entering the block.
        - The block of code should be indented after the `yield` statement.
        - Garbage collection will be invoked with `gc.collect()` before exiting the block, regardless of the value of `disable_gc`.
        - If `disable_gc` is True, garbage collection will be enabled after exiting the block.
    """
    if disable_gc:
        gc.disable()

    try:
        yield
    finally:
        gc.collect()

    if disable_gc:
        gc.enable()


__all__ = ("force_gc",)
