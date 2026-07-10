`rls_transaction` now falls back directly to the primary DB for connection-level mid-query read replica failures via `execute_wrapper`, reducing non-streaming read crashes during replica recovery
