FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        curl && \
    curl -L https://github.com/mikefarah/yq/releases/download/v4.50.1/yq_linux_amd64 \
        -o /usr/local/bin/yq && \
    chmod +x /usr/local/bin/yq && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Copy entrypoint script
COPY config/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /app/pcaps

ENTRYPOINT [ "/entrypoint.sh" ]