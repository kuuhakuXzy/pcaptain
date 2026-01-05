// constant.js
const API_PATH = Object.freeze({
    PCAP_REINDEX_PATH: "reindex",
    PCAP_SEARCHING_PATH: "search",
    SERVER_HEALTH_CHECK_PATH: "health",
    SCAN_STATUS_PATH: "scan-status",
    SEARCH_SUGGESTION: "protocols/suggest",
    CANCEL_SCAN_PATH: "cancel-scan"
});

const TOAST_STATUS = Object.freeze({
    SUCCESS: "Success",
    WARNING: "Warning",
    NOT_FOUND: "Not found",
    ERROR: "Error",
    INFO: "Info"
});

const SERVER_SCANNING_FILE_STATUS = Object.freeze({
    IDLE: "idle",
    RUNNING: "running",
    COMPLETED: "completed",
    FAILED: "failed"
});

const SERVER_HEALTH_CHECK_INTERVAL = 20000; // millisecond
const CHECK_SCAN_FILES_STATUS_INTERVAL = 2000; // millisecond
const MIN_QUERY_LENGTH = 1;

export {
    API_PATH,
    CHECK_SCAN_FILES_STATUS_INTERVAL,
    MIN_QUERY_LENGTH,
    SERVER_HEALTH_CHECK_INTERVAL,
    SERVER_SCANNING_FILE_STATUS,
    TOAST_STATUS
}

// const SERVER = "http://192.168.56.101:8080/packet-capture-service";
// const PCAP_REINDEX_PATH = "/api/v2/protocol/scan";
// const PCAP_SEARCHING_PATH = "/api/v2/protocol/search";
// const PCAP_DOWNLOAD_PATH = "/api/v2/protocol/download";