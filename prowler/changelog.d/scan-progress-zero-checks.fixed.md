`Scan.progress` now returns 0 instead of raising `ZeroDivisionError` when a scan has no checks to execute, which happens when a severity or category filter matches nothing
