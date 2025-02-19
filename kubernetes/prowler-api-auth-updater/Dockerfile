FROM --platform=linux/amd64 python:3.12-slim

WORKDIR /app

COPY /src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/main.py .

CMD ["python", "/app/main.py"]