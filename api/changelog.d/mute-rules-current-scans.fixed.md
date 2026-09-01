`POST /api/v1/mute-rules` now updates only each affected provider's latest completed scan and future scans, preventing historical reaggregation from flooding Celery queues
