FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends tshark wireshark-common && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN pip install backoff

COPY . .

RUN mkdir -p /app/pcaps

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${BE_INTERNAL_PORT:-8000}"]
