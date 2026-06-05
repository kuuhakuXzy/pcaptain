"""Redis keys and prefixes for the network catalog extensions."""

PCAP_FILE_KEY_PREFIX = "pcap:file"
PROTOCOL_INDEX_PREFIX = "pcap:index:protocol"
IP_INDEX_PREFIX = "pcap:index:ip"
PORT_INDEX_PREFIX = "pcap:index:port"

SORT_INDEX_PREFIX = "pcap:sort"
SORT_INDEX_FILENAME = f"{SORT_INDEX_PREFIX}:filename"
SORT_INDEX_PATH = f"{SORT_INDEX_PREFIX}:path"
SORT_INDEX_SIZE = f"{SORT_INDEX_PREFIX}:size_bytes"
SORT_INDEX_PACKET_COUNT = f"{SORT_INDEX_PREFIX}:protocol_packet_count"
SORT_INDEX_CAPTURE_START = f"{SORT_INDEX_PREFIX}:capture_start"

TMP_RESULT_PREFIX = "pcap:tmp:search"
TMP_KEY_TTL_SECONDS = 5

STATS_SUMMARY_KEY = "catalog:stats:summary"
WEBHOOKS_CONFIG_KEY = "catalog:webhooks"
KNOWN_IPS_KEY = "catalog:known:ips"
NEW_IPS_SNAPSHOT_KEY = "catalog:ips:new:last"
SCAN_FAILURES_KEY = "catalog:scan:failures"
SCAN_FAILURES_MAX = 200
