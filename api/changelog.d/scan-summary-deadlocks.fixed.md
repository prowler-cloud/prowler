`scan-summary` aggregation now upserts summaries in deterministic conflict-key order, preventing PostgreSQL deadlocks during concurrent reaggregation
