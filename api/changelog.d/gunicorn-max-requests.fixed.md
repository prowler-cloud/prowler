Gunicorn workers are now recycled after 10000 requests (plus up to 1000 of jitter) to cap memory growth, configurable with `GUNICORN_MAX_REQUESTS` and `GUNICORN_MAX_REQUESTS_JITTER`
