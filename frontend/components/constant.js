// constant.js
const API_PATH = Object.freeze({
    PCAP_REINDEX_PATH: "reindex",
    PCAP_SEARCHING_PATH: "search",
    FUZZY_SEARCH_PATH: "search/ft",
    SERVER_HEALTH_CHECK_PATH: "health",
    HEALTH_READY_PATH: "health/ready",
    SCAN_STATUS_PATH: "scan-status",
    SEARCH_SUGGESTION: "protocols/suggest",
    SCAN_CANCEL_PATH: "scan-cancel",
    DASHBOARD_SUMMARY_PATH: "dashboard-summary",
    SCAN_CONFIG_PATH: "scan-config",
    CATALOG_QUERY_PATH: "query",
    CATALOG_ENDPOINTS_PATH: "search/endpoints",
    STATS_OVERVIEW_PATH: "stats/overview",
    STATS_PROTOCOLS_PATH: "stats/protocols",
    STATS_DIRECTORIES_PATH: "stats/directories",
    STATS_CO_OCCURRENCE_PATH: "stats/co-occurrence",
    STATS_TOP_TALKERS_PATH: "stats/top-talkers",
    INDEX_EXPORT_PATH: "index/export",
    INDEX_IMPORT_PATH: "index/import",
    WEBHOOKS_PATH: "webhooks",
    BACKFILL_ENDPOINTS_PATH: "backfill/endpoints",
    HEALTH_DASHBOARD_PATH: "health/dashboard",
    CATALOG_DUPLICATES_PATH: "catalog/duplicates",
    CATALOG_ORPHANS_PATH: "catalog/orphans",
    SEARCH_SUBNET_PATH: "search/subnet",
    CATALOG_NEW_IPS_PATH: "catalog/ips/new",
    CATALOG_IPS_RESET_PATH: "catalog/ips/reset-baseline",
    CATALOG_IPS_SNAPSHOT_PATH: "catalog/ips/snapshot",
    SCAN_FOLDERS_PATH: "scan/folders",
    REINDEX_FOLDER_PATH: "reindex/folder",
    PCAP_MERGE_PATH: "pcaps/merge"
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

const SERVER = new URL(window.APP_CONFIG.BE_BASE_URL).href;

export {
    API_PATH,
    CHECK_SCAN_FILES_STATUS_INTERVAL,
    MIN_QUERY_LENGTH,
    SERVER,
    SERVER_HEALTH_CHECK_INTERVAL,
    SERVER_SCANNING_FILE_STATUS,
    TOAST_STATUS
}


export const SCAN_MODE_TEXT = {
    full: "Full",
    normal: "Full",
    quick: "Quick",
    fast: "Fast"
};


// const SERVER = "http://192.168.56.101:8080/packet-capture-service";
// const PCAP_REINDEX_PATH = "/api/v2/protocol/scan";
// const PCAP_SEARCHING_PATH = "/api/v2/protocol/search";
// const PCAP_DOWNLOAD_PATH = "/api/v2/protocol/download";