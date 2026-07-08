Compliance overview ingest now runs in a single transaction per scan with a configurable `COPY` batch size (`DJANGO_COMPLIANCE_COPY_BATCH_SIZE`, default 2000), reducing write pressure on the database
