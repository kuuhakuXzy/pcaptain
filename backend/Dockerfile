FROM gcc:13-bookworm as fastscan-builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev && \
    rm -rf /var/lib/apt/lists/

COPY fast_scan/fast_scan.cpp .
COPY fast_scan/well_known_port.h .

RUN g++ -O3 -std=c++17 fast_scan.cpp -lpcap -o fastscan

FROM python:3.10-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        curl && \
    curl -L https://github.com/mikefarah/yq/releases/download/v4.50.1/yq_linux_amd64 \
        -o /usr/local/bin/yq && \
    chmod +x /usr/local/bin/yq && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled fastscan binary
COPY --from=fastscan-builder /build/fastscan /usr/local/bin/fastscan

WORKDIR /app

COPY backend/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY backend . 
# Copy entrypoint script
COPY backend/config/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /app/pcaps

ENTRYPOINT [ "/entrypoint.sh" ]