#!/bin/sh
set -e

CONFIG_FILE="/app/config/config.yaml"

echo "Loading configuration..."

# Ensure config file exists
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Config file not found, creating empty config"
  mkdir -p "$(dirname "$CONFIG_FILE")"
  echo "{}" > "$CONFIG_FILE"
fi

# Update config only if env vars are set
if [ -n "$PORT" ]; then
  yq -i '.port = env(PORT)' "$CONFIG_FILE"
fi

if [ -n "$PUBLIC_URL" ]; then
  yq -i '.public_url = env(PUBLIC_URL)' "$CONFIG_FILE"
fi

if [ -n "$REDIS_HOST" ]; then
  yq -i '.redis.host = env(REDIS_HOST)' "$CONFIG_FILE"
fi

if [ -n "$REDIS_PORT" ]; then
  yq -i '.redis.port = env(REDIS_PORT)' "$CONFIG_FILE"
fi

if [ -n "$PCAP_ROOT_DIRECTORY" ]; then
  yq -i '.pcap.root_directory = env(PCAP_ROOT_DIRECTORY)' "$CONFIG_FILE"
fi

if [ -n "$PCAP_PREFIX_STR" ]; then
  yq -i '.pcap.prefix_str = env(PCAP_PREFIX_STR)' "$CONFIG_FILE"
fi

if [ -n "$PCAP_SCAN_INTERVAL_SECONDS" ]; then
  yq -i '.pcap.scan_interval_seconds = env(PCAP_SCAN_INTERVAL_SECONDS)' "$CONFIG_FILE"
fi

if [ -n "$SCAN_MODE" ]; then
  yq -i '.pcap.scan_mode = env(SCAN_MODE)' "$CONFIG_FILE"
fi

# Quick scan (tshark sampling) settings

if [ -n "$QUICK_SCAN_PEBC" ]; then
  yq -i '.pcap.quick_scan.pebc = env(QUICK_SCAN_PEBC)' "$CONFIG_FILE"
fi

if [ -n "$QUICK_SCAN_MIN_FILE_SIZE" ]; then
  yq -i '.pcap.quick_scan.min_file_size = env(QUICK_SCAN_MIN_FILE_SIZE)' "$CONFIG_FILE"
fi

if [ -n "$QUICK_SCAN_CONFIG_VERSION" ]; then
  yq -i '.pcap.quick_scan.config_version = env(QUICK_SCAN_CONFIG_VERSION)' "$CONFIG_FILE"
fi

if [ -n "$LOG_LEVEL" ]; then
  yq -i '.log.level = env(LOG_LEVEL)' "$CONFIG_FILE"
fi

echo "Final configuration:"
cat "$CONFIG_FILE"

# Determine port (config > env > default)
PORT="$(yq '.port // env(PORT) // 8000' "$CONFIG_FILE")"

echo "Starting uvicorn on port ${PORT}..."

exec uvicorn main:app \
  --host 0.0.0.0 \
  --port "$PORT"
