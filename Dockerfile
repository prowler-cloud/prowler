FROM python:3.11.9-slim

COPY requirements.txt /requirements.txt
COPY be_poc /be_poc

RUN python -m pip install -r /requirements.txt
WORKDIR /be_poc
RUN python manage.py migrate && \
    python manage.py loaddata dummy_accounts

ENTRYPOINT ["python", "manage.py", "runserver", "0.0.0.0:8000"]
