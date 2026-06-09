import { showToast } from "./toast-script.js";
import {
    API_PATH,
    CHECK_SCAN_FILES_STATUS_INTERVAL,
    MIN_QUERY_LENGTH,
    SCAN_MODE_TEXT,
    SERVER,
    SERVER_HEALTH_CHECK_INTERVAL,
    SERVER_SCANNING_FILE_STATUS,
    TOAST_STATUS
} from "./constant.js";
import { openInfoModal } from "./info-modal.js";
import {
    SEARCH_FAST_IDS,
    applyFastScanPreset,
    collectFastScanOptions,
    formatFastScanOptionsSummary,
    isFastScanMode,
    loadFastScanPrefs,
    saveFastScanPrefs,
    updateFastScanOptionsPanel,
    updateFastScanSummary,
    updateScanModeBadge,
    wireFastScanOptionToggles,
} from "./fast-scan-options.js";


// --- STATE MANAGEMENT ---
let currentPage = 1;
let itemsPerPage = 5;
let currentSortBy = "filename";
let currentDescending = false;
let currentFiles = []; // Store current page's files for copy functionality
let lastFetchTotal = 0;
let investigatorQuery = null; // { ip, port? } — IP investigator workflow
let scan_state = false; // Track whether scanning is active
let scanStatusTimer = null; // Store the interval timer
let cachedScanConfig = null;
let timerInterval = null; // Time variable that a fuction needs to operate it's logic



// --- UI HELPERS ---
function displaySearchLoadingSpinner() {
    const spinner = document.getElementById("spinnerSearchBtn");
    const searchBtn = document.getElementById("searchBtn");
    if (spinner) {
        spinner.classList.remove("spinner-search-hidden");
        spinner.classList.add("spinner-search-visible");
    }
    if (searchBtn) searchBtn.style.display = "none";
}

function startTimer() { // Functions that starts the timer
    const timerElement = document.getElementById("timer");
    const timeContainer = document.getElementById("timeContainer")

    let startTime = Date.now();
    timerElement.innerText = "0.0";
    timeContainer.style.display = "block";
    // console.log("Timer started");

    if (timerInterval)
        clearInterval(timerInterval);

    timerInterval = setInterval(() => {
        let secondsPassed = ((Date.now() - startTime) / 1000).toFixed(1);
        // this code ensure that even if the browser gets delayed, it wont affect the timer, i guess..., i dont have pcap file large enough to test my theory lol(and the timer is rounded btw)
        timerElement.innerText = secondsPassed;
        console.log(`Waiting: ${secondsPassed} secs...`);
    }, 100);
}

function stopTimer() {// Functions that ends the timer and reset it
    if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;

        const finalSeconds = document.getElementById("timer").innerText;

        // console.log(`Totall runtime ${finalSeconds}`);
    }
    else {
        // console.log("stopTimer did work, but startTimer didnt");

    }
}

function disappearSearchLoadingSpinner() {
    const spinner = document.getElementById("spinnerSearchBtn");
    const searchBtn = document.getElementById("searchBtn");
    if (spinner) {
        spinner.classList.add("spinner-search-hidden");
        spinner.classList.remove("spinner-search-visible");
    }
    if (searchBtn) searchBtn.style.display = "inline-block";
}

async function loadScanConfigTooltip() {
    // Pull runtime scan configuration for the global tooltip.
    const tooltipContent = document.getElementById("scanConfigTooltipContent");
    if (!tooltipContent) {
        return;
    }
    try {
        const response = await axios.get(SERVER + API_PATH.SCAN_CONFIG_PATH);
        const config = response.data || {};
        cachedScanConfig = config;
        updateFastScanOptionsPanel(SEARCH_FAST_IDS, config);
        updateScanModeBadge("scanModeBadge", config);
        const scanModeLabel = SCAN_MODE_TEXT[config.scan_mode] || "Full";
        const pebcLabel =
            config.scan_mode === "quick" && config.pebc !== null && config.pebc !== undefined && config.pebc !== ""
                ? config.pebc
                : "N/A";
        const minFileSize = config.min_file_size || "0";
        const configVersion = config.config_version || "v1";
        if (config.scan_mode === "full") {
            tooltipContent.textContent = `Scan Mode: ${scanModeLabel}`;
        } else {
            tooltipContent.textContent =
                `Scan Mode: ${scanModeLabel}\n` +
                `PEBC: ${pebcLabel}\n` +
                `Min File Size: ${minFileSize}\n` +
                `Config Version: ${configVersion}`;
        }
    } catch (err) {
        tooltipContent.textContent = "Scan config unavailable";
    }
}

//check scan status
function startScanStatusPolling() {
    if (scanStatusTimer) {
        clearInterval(scanStatusTimer);
        scanStatusTimer = null;
    }
    scanStatusTimer = setInterval(async () => {
        try {
            const apiResponse = await axios.get(SERVER + API_PATH.SCAN_STATUS_PATH);
            const status = apiResponse.data.state;
            if (status === SERVER_SCANNING_FILE_STATUS.COMPLETED ||
                status === SERVER_SCANNING_FILE_STATUS.IDLE
            ) {
                disappearScanLoadingSpinner();
                clearInterval(scanStatusTimer);
                scanStatusTimer = null;
                stopTimer();
                showToast(TOAST_STATUS.SUCCESS, "Scan completed successfully");
                fetchFiles();
                serverHealthCheck();
                refreshNewIpBanner();
            }
            else if (status === SERVER_SCANNING_FILE_STATUS.FAILED) {
                disappearScanLoadingSpinner();
                clearInterval(scanStatusTimer);
                scanStatusTimer = null;
                stopTimer();
                showToast(TOAST_STATUS.ERROR, "Scan failed");
            }
        } catch (err) {
            disappearScanLoadingSpinner();
            clearInterval(scanStatusTimer);
            scanStatusTimer = null;
            stopTimer();
        }
    }, CHECK_SCAN_FILES_STATUS_INTERVAL);
}

function getFilterValue(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : "";
}

function hasAdvancedFilters() {
    return Boolean(
        getFilterValue("filterIp") ||
        getFilterValue("filterPort") ||
        getFilterValue("filterFilename") ||
        getFilterValue("filterPathPrefix") ||
        getFilterValue("filterSizeMin") ||
        getFilterValue("filterSizeMax") ||
        getFilterValue("filterSubnet")
    );
}

function clearAdvancedFilters() {
    ["filterIp", "filterPort", "filterSubnet", "filterFilename", "filterPathPrefix", "filterSizeMin", "filterSizeMax"].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.value = "";
    });
}

function buildCatalogQueryBody() {
    const protocolQuery = document.getElementById("searchInput").value.trim();
    const body = {
        protocol_query: protocolQuery,
        page: currentPage,
        limit: itemsPerPage,
        sort_by: currentSortBy,
        descending: currentDescending
    };

    const filename = getFilterValue("filterFilename");
    if (filename) body.filename_contains = filename;

    const pathPrefix = getFilterValue("filterPathPrefix");
    if (pathPrefix) body.path_prefix = pathPrefix;

    const sizeMinMb = parseFloat(getFilterValue("filterSizeMin"));
    const sizeMaxMb = parseFloat(getFilterValue("filterSizeMax"));
    if (!Number.isNaN(sizeMinMb) && sizeMinMb > 0) {
        body.size_bytes = { ...(body.size_bytes || {}), min: Math.floor(sizeMinMb * 1024 * 1024) };
    }
    if (!Number.isNaN(sizeMaxMb) && sizeMaxMb > 0) {
        body.size_bytes = { ...(body.size_bytes || {}), max: Math.floor(sizeMaxMb * 1024 * 1024) };
    }

    const ip = getFilterValue("filterIp");
    if (ip) body.ip = ip;

    const portRaw = getFilterValue("filterPort");
    if (portRaw) {
        const port = parseInt(portRaw, 10);
        if (port >= 1 && port <= 65535) body.port = port;
    }

    return body;
}

function shouldUseSubnetSearch() {
    if (investigatorQuery) return false;
    return Boolean(getFilterValue("filterSubnet"));
}

function shouldUseEndpointSearchOnly() {
    if (investigatorQuery) return true;
    if (shouldUseSubnetSearch()) return false;
    const protocolQuery = document.getElementById("searchInput").value.trim();
    const ip = getFilterValue("filterIp");
    const port = getFilterValue("filterPort");
    return (ip || port) && !protocolQuery && !getFilterValue("filterFilename") && !getFilterValue("filterPathPrefix");
}

function clearInvestigatorQuery() {
    investigatorQuery = null;
}

function canRunSearch() {
    const protocolQuery = document.getElementById("searchInput").value.trim();
    return Boolean(protocolQuery || hasAdvancedFilters());
}

// Helper function
function smartFetch() {
    fetchFiles();
}

document.getElementById("searchBtn").addEventListener("click", () => {
    const search = document.getElementById("searchInput").value.trim();

    if (isSearchMode) {
        return clearSearchAndShowAll();
    }

    if (!canRunSearch()) {
        return showToast(TOAST_STATUS.WARNING, "Enter a protocol query or use Advanced filters");
    }

    clearInvestigatorQuery();
    currentPage = 1; // Reset to page 1 on new search
    fetchFiles();
    setSearchMode(true);
})

const searchInput = document.getElementById("searchInput");
const searchBtn = document.getElementById("searchBtn");

// Search/Clear mode state
let isSearchMode = false;

function setSearchMode(on) {
    isSearchMode = on;
    if (!searchBtn) return;

    if (on) {
        searchBtn.textContent = "Clear";
        searchBtn.title = "Clear search and show all files";
    } else {
        searchBtn.textContent = "Search";
        searchBtn.title = "Search";
    }
}

function clearSearchAndShowAll() {
    searchInput.value = "";
    clearAdvancedFilters();
    clearInvestigatorQuery();
    currentPage = 1;

    if (typeof hideSuggestion === "function") hideSuggestion();

    setSearchMode(false);
    fetchFiles();
}

function browseAllFiles() {
    searchInput.value = "";
    clearAdvancedFilters();
    clearInvestigatorQuery();
    currentPage = 1;
    if (typeof hideSuggestion === "function") hideSuggestion();
    setSearchMode(false);
    fetchFiles();
}

searchInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        const search = document.getElementById("searchInput").value.trim();
        if (!canRunSearch()) {
            return showToast(TOAST_STATUS.WARNING, "Enter a protocol query or use Advanced filters");
        }
        clearInvestigatorQuery();
        currentPage = 1; // Reset to page 1 on new search
        hideSuggestion();
        fetchFiles();
        setSearchMode(true);
    }
});

document.getElementById("toggleAdvancedBtn")?.addEventListener("click", () => {
    const panel = document.getElementById("advancedFiltersPanel");
    if (panel) panel.classList.toggle("hidden");
});

document.getElementById("browseAllBtn")?.addEventListener("click", browseAllFiles);

["filterIp", "filterPort", "filterSubnet", "filterFilename", "filterPathPrefix", "filterSizeMin", "filterSizeMax"].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("change", () => {
        currentPage = 1;
    });
});

const sortBySelect = document.getElementById("sortBy");
const sortOrderSelect = document.getElementById("sortOrder");
const limitSelect = document.getElementById("limitSelect");

if (limitSelect) limitSelect.value = "5";
if (sortBySelect) sortBySelect.value = "filename";
if (sortOrderSelect) sortOrderSelect.value = "false";

loadScanConfigTooltip();

// Listen to user's items per page
if (limitSelect) {
    limitSelect.addEventListener("change", (e) => {
        itemsPerPage = parseInt(e.target.value);
        currentPage = 1;
        smartFetch();
    });
}

if (sortBySelect) {
    sortBySelect.addEventListener("change", (e) => {
        currentSortBy = e.target.value;
        currentPage = 1;
        smartFetch();
    });
}

if (sortOrderSelect) {
    sortOrderSelect.addEventListener("change", (e) => {
        currentDescending = e.target.value === "true";
        currentPage = 1;
        smartFetch();
    });
}

const suggestionBox = document.getElementById("suggestionBox");
document.addEventListener("click", (e) => {
    if (!searchInput.contains(e.target) && !suggestionBox.contains(e.target)) {
        hideSuggestion();
    }
});

searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        hideSuggestion();
    }
});

searchInput.addEventListener("input", async () => {
    const input = searchInput.value.toLowerCase().trim();
    if (input.length < MIN_QUERY_LENGTH) {
        hideSuggestion();
        return;
    }
    await fetchSuggestion(input);
});

async function fetchSuggestion(input) {
    try {
        const apiResponse = await axios.get(
            SERVER + API_PATH.SEARCH_SUGGESTION,
            { params: { q: input } }
        );
        if (!apiResponse) {
            showToast(TOAST_STATUS.ERROR, "Failed to fetch search suggestion")
        }
        renderSuggestion(input, apiResponse.data);
    } catch (err) {
        console.log("Error while fetching search suggestion: ", err);
    }
}

function renderSuggestion(input, data) {
    if (!data || !data.length) {
        hideSuggestion();
        return;
    }
    suggestionBox.innerHTML = "";
    data.forEach(item => {
        const div = document.createElement("div");
        div.className = "suggestion-item";
        const regex = new RegExp(`(${escapeRegExp(input)})`, "gi");
        const html = item.replace(regex, "<strong>$1</strong>");
        div.innerHTML = html;

        div.addEventListener("click", () => {
            searchInput.value = item;
            hideSuggestion();
            currentPage = 1;
            fetchFiles();
        });

        suggestionBox.appendChild(div);
    });
    suggestionBox.classList.remove("hidden");
}

function hideSuggestion() {
    suggestionBox.classList.add("hidden");
    suggestionBox.innerHTML = "";
}

function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function loadScanFolderOptions() {
    const sel = document.getElementById("scanFolderSelect");
    if (!sel) return;
    try {
        const res = await axios.get(SERVER + API_PATH.SCAN_FOLDERS_PATH);
        const folders = res.data?.folders || [];
        sel.innerHTML = '<option value="">— Entire tree —</option>';
        for (const f of folders) {
            const opt = document.createElement("option");
            opt.value = f.name;
            opt.textContent = `${f.name} (${f.pcap_count_hint}+ pcap)`;
            sel.appendChild(opt);
        }
    } catch (_) {
        /* keep default option */
    }
}

document.getElementById("scanBtn").addEventListener("click", async () => {
    document.getElementById("scanModal").classList.remove("hidden");
    if (!cachedScanConfig) {
        try {
            const response = await axios.get(SERVER + API_PATH.SCAN_CONFIG_PATH);
            cachedScanConfig = response.data || {};
            updateFastScanOptionsPanel(SEARCH_FAST_IDS, cachedScanConfig);
            updateScanModeBadge("scanModeBadge", cachedScanConfig);
        } catch (_) {
            /* panel stays hidden */
        }
    } else {
        updateFastScanOptionsPanel(SEARCH_FAST_IDS, cachedScanConfig);
    }
    loadScanFolderOptions();
});

document.getElementById("fastScanPresets")?.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-preset]");
    if (!btn || !cachedScanConfig) return;
    applyFastScanPreset(SEARCH_FAST_IDS, cachedScanConfig, btn.dataset.preset);
});

document.getElementById("closeModalBtn").addEventListener("click", () => {
    document.getElementById("scanModal").classList.add("hidden");
});

// Scan all button
function displayScanLoadingSpinner() {
    const spinner = document.getElementById("spinnerScanBtn");
    const scanBtn = document.getElementById("scanBtn");
    const cancelBtn = document.getElementById("cancelScanBtn");
    if (spinner) {
        spinner.classList.remove("spinner-scan-hidden");
        spinner.classList.add("spinner-scan-visible");
    }
    if (scanBtn) scanBtn.style.display = "none";
    if (cancelBtn) cancelBtn.disabled = false;
}

function disappearScanLoadingSpinner() {
    const spinner = document.getElementById("spinnerScanBtn");
    const scanBtn = document.getElementById("scanBtn");
    const cancelBtn = document.getElementById("cancelScanBtn");
    if (spinner) {
        spinner.classList.add("spinner-scan-hidden");
        spinner.classList.remove("spinner-scan-visible");
    }
    if (scanBtn) scanBtn.style.display = "inline-block";
    if (cancelBtn) cancelBtn.disabled = true;
}

document.getElementById("scanAllBtn").addEventListener("click", async () => {
    const scanModal = document.getElementById("scanModal");
    scanModal.classList.add("hidden");
    const folder = document.getElementById("scanFolderSelect")?.value?.trim() || "";
    await scanFiles(folder || null);
});

document.getElementById("cancelScanBtn").addEventListener("click", async () => {
    try {
        await axios.post(SERVER + API_PATH.SCAN_CANCEL_PATH);
        if (scanStatusTimer) {
            clearInterval(scanStatusTimer);
            scanStatusTimer = null;
        }
        disappearScanLoadingSpinner();
        stopTimer();
        showToast(TOAST_STATUS.INFO, "Scan cancelled");
    }
    catch (err) {
        showToast(TOAST_STATUS.ERROR, "Failed to cancel scan");
    }
});


const chooseDirBtn = document.getElementById("chooseDirBtn");
if (chooseDirBtn) {
    chooseDirBtn.addEventListener("click", () => {
        alert("Choose a specific directory...");
        document.getElementById("scanModal").classList.add("hidden");
    });
}

async function serverHealthCheck() {
    const statusSignal = document.querySelector(".status-signal");
    if (!statusSignal) return;

    try {
        const apiResponse = await axios.get(SERVER + API_PATH.SERVER_HEALTH_CHECK_PATH);
        if (apiResponse.data.status !== "OK") {
            statusSignal.innerHTML = `<i class="fa fa-circle status-bad"></i><span>Server Error</span>`;
            return;
        }
        try {
            const ready = await axios.get(SERVER + API_PATH.HEALTH_READY_PATH);
            const indexed = ready.data?.indexed_files ?? "?";
            const scanState = ready.data?.scan_state || "idle";
            const label =
                ready.data?.status === "ready"
                    ? `Online · ${indexed} indexed · scan ${scanState}`
                    : `Degraded · ${indexed} indexed`;
            statusSignal.innerHTML = `<i class="fa fa-circle status-ok"></i><span>${label}</span>`;
        } catch (_) {
            statusSignal.innerHTML = `<i class="fa fa-circle status-ok"></i><span>Online</span>`;
        }
    } catch (err) {
        console.log("Health check failed", err);
        statusSignal.innerHTML = `<i class="fa fa-circle status-bad"></i><span>Server Error</span>`;
    }
}
serverHealthCheck();
setInterval(serverHealthCheck, SERVER_HEALTH_CHECK_INTERVAL);

// --- SCAN STATE MANAGEMENT ---
function manageScanState() {
    const cancelBtn = document.getElementById("cancelScanBtn");

    if (scan_state) {
        // Start interval polling if not already running
        if (!scanStatusTimer) {
            scanStatusTimer = setInterval(async () => {
                try {
                    const apiResponse = await axios.get(SERVER + API_PATH.SCAN_STATUS_PATH);
                    const status = apiResponse.data.state;

                    if (status === SERVER_SCANNING_FILE_STATUS.COMPLETED ||
                        status === SERVER_SCANNING_FILE_STATUS.IDLE
                    ) {
                        scan_state = false;
                        manageScanState(); // This will clear the interval
                        disappearScanLoadingSpinner();
                        if (cancelBtn) cancelBtn.classList.add("hidden");
                        stopTimer();
                        showToast(TOAST_STATUS.SUCCESS, "Scan completed successfully");
                        fetchFiles();
                        serverHealthCheck();
                    } else if (status === SERVER_SCANNING_FILE_STATUS.FAILED) {
                        scan_state = false;
                        manageScanState(); // This will clear the interval
                        disappearScanLoadingSpinner();
                        if (cancelBtn) cancelBtn.classList.add("hidden");
                        stopTimer();
                        showToast(TOAST_STATUS.ERROR, "Scan failed");
                    }
                } catch (err) {
                    console.error("Error checking scan status:", err);
                    scan_state = false;
                    manageScanState(); // This will clear the interval
                    disappearScanLoadingSpinner();
                    if (cancelBtn) cancelBtn.classList.add("hidden");
                    stopTimer();
                }
            }, CHECK_SCAN_FILES_STATUS_INTERVAL);
        }
    } else {
        // Stop interval polling
        if (scanStatusTimer) {
            clearInterval(scanStatusTimer);
            scanStatusTimer = null;
        }
    }
}

async function scanFiles(targetFolder = null) {
    displayScanLoadingSpinner();

    if (scanStatusTimer) {
        clearInterval(scanStatusTimer);
        scanStatusTimer = null;
    }

    try {
        const fastOpts = collectFastScanOptions(SEARCH_FAST_IDS, cachedScanConfig);
        const body = {
            folder: targetFolder || null,
        };
        if (fastOpts) {
            body.fast_options = fastOpts;
            saveFastScanPrefs(fastOpts);
        }
        const apiResponse = await axios.post(SERVER + API_PATH.PCAP_REINDEX_PATH, body);
        startTimer();
        const params = targetFolder ? { folder: targetFolder } : {};
        const apiResponse = await axios.post(SERVER + API_PATH.PCAP_REINDEX_PATH, null, { params });
        if (!apiResponse) {
            disappearScanLoadingSpinner();
            return showToast(TOAST_STATUS.ERROR, "Failed to trigger scan");
        }
        if (isFastScanMode(cachedScanConfig) && fastOpts) {
            showToast(TOAST_STATUS.SUCCESS, formatFastScanOptionsSummary(fastOpts));
        }
        startScanStatusPolling();
        //const timer = setInterval(async () => {
        /*scanStatusTimer = setInterval(async () => {
            try {
                const apiResponse = await axios.get(SERVER + API_PATH.SCAN_STATUS_PATH);
                const status = apiResponse.data.state;
                if (status === SERVER_SCANNING_FILE_STATUS.COMPLETED ||
                    status === SERVER_SCANNING_FILE_STATUS.IDLE
                ) {
                    disappearScanLoadingSpinner();
                    clearInterval(scanStatusTimer);
                    scanStatusTimer = null;
                    showToast(TOAST_STATUS.SUCCESS, "Scan completed successfully");
                } else if (status === SERVER_SCANNING_FILE_STATUS.FAILED) {
                    disappearScanLoadingSpinner();
                    clearInterval(scanStatusTimer);
                    showToast(TOAST_STATUS.ERROR, "Scan failed");
                }
            } catch (err) {
                disappearScanLoadingSpinner();
                clearInterval(scanStatusTimer);
                scanStatusTimer = null;
            }
        }, CHECK_SCAN_FILES_STATUS_INTERVAL); */ //alr replaced with startScanStatusPolling
    } catch (err) {
        disappearScanLoadingSpinner();
        stopTimer();
        if (cancelBtn) cancelBtn.classList.add("hidden");
        console.error("API error: ", err);
        showToast(TOAST_STATUS.ERROR, "Error triggering scan");
    }
}

async function syncScanStateOnLoad() {
    try {
        const res = await axios.get(SERVER + API_PATH.SCAN_STATUS_PATH);
        if (res.data.state === SERVER_SCANNING_FILE_STATUS.RUNNING) {
            displayScanLoadingSpinner();
            startScanStatusPolling();
        }
        else {
            disappearScanLoadingSpinner();
        }
    } catch (_) {
        // keep default UI
    }
}

syncScanStateOnLoad();
fetchFiles();
refreshNewIpBanner();

async function fetchFiles() {
    try {
        displaySearchLoadingSpinner();
        startTimer();

        const params = { protocol: search, page: currentPage, limit: itemsPerPage, sort_by: currentSortBy, descending: currentDescending };

        const apiResponse = await requestSearchPage(currentPage, itemsPerPage);

        disappearSearchLoadingSpinner();
        stopTimer();

        if (!apiResponse || !apiResponse.data) {
            showToast(TOAST_STATUS.ERROR, "Failed to get response");
            return { total: 0, shown: 0 };
        }

        const responseData = apiResponse.data;
        const files = responseData.data;
        const totalItems = responseData.total;
        lastFetchTotal = totalItems;

        currentFiles = files;

        renderTable(files);
        updatePaginationControls(totalItems);
        return { total: totalItems, shown: files.length };
    } catch (err) {
        disappearSearchLoadingSpinner();
        stopTimer();
        console.error("API error: ", err);
        const detail = err.response?.data?.detail;
        const msg = typeof detail === "string" ? detail : "Error while searching files";
        showToast(TOAST_STATUS.ERROR, msg);
        throw new Error(msg);
    }
}

async function requestSearchPage(page, limit) {
    if (shouldUseSubnetSearch()) {
        const cidr = getFilterValue("filterSubnet");
        return axios.get(SERVER + API_PATH.SEARCH_SUBNET_PATH, {
            params: { cidr, page, limit }
        });
    }
    if (shouldUseEndpointSearchOnly()) {
        const params = { page, limit };
        const ip = investigatorQuery?.ip || getFilterValue("filterIp");
        const portRaw = investigatorQuery?.port ?? getFilterValue("filterPort");
        if (ip) params.ip = ip;
        if (portRaw !== "" && portRaw != null) {
            const port = typeof portRaw === "number" ? portRaw : parseInt(portRaw, 10);
            if (!Number.isNaN(port)) params.port = port;
        }
        return axios.get(SERVER + API_PATH.CATALOG_ENDPOINTS_PATH, { params });
    }
    return axios.post(SERVER + API_PATH.CATALOG_QUERY_PATH, {
        ...buildCatalogQueryBody(),
        page,
        limit
    });
}

async function fetchAllMatchingFiles(maxTotal = 500) {
    const all = [];
    const pageSize = 50;
    let page = 1;

    while (all.length < maxTotal) {
        const res = await requestSearchPage(page, pageSize);
        const batch = res.data?.data || [];
        const total = res.data?.total ?? 0;
        all.push(...batch);
        if (batch.length === 0 || all.length >= total) break;
        page += 1;
    }

    return all.slice(0, maxTotal);
}

function escapeCsvCell(value) {
    const text = String(value ?? "");
    if (/[",\n\r]/.test(text)) {
        return `"${text.replace(/"/g, '""')}"`;
    }
    return text;
}

function filesToCsv(files) {
    const header = [
        "filename",
        "path",
        "size_bytes",
        "total_packets",
        "capture_start",
        "capture_end",
        "scan_mode",
        "indexed_ips",
        "indexed_ports"
    ];
    const lines = [header.join(",")];
    for (const f of files) {
        lines.push(
            [
                escapeCsvCell(f.filename),
                escapeCsvCell(f.path),
                escapeCsvCell(f.size_bytes),
                escapeCsvCell(f.total_packets),
                escapeCsvCell(f.capture_start),
                escapeCsvCell(f.capture_end),
                escapeCsvCell(f.scan_mode),
                escapeCsvCell(f.indexed_ips),
                escapeCsvCell(f.indexed_ports)
            ].join(",")
        );
    }
    return lines.join("\n");
}

async function runIpInvestigation(ip, port) {
    investigatorQuery = { ip, port: port ?? null };

    const filterIp = document.getElementById("filterIp");
    const filterPort = document.getElementById("filterPort");
    if (filterIp) filterIp.value = ip;
    if (filterPort) filterPort.value = port != null ? String(port) : "";

    searchInput.value = "";
    currentPage = 1;
    setSearchMode(true);

    return fetchFiles();
}

async function copyAllMatchingPaths() {
    if (lastFetchTotal === 0) {
        showToast(TOAST_STATUS.WARNING, "No results to copy");
        return;
    }
    showToast(TOAST_STATUS.INFO, "Fetching paths…");
    try {
        const files = await fetchAllMatchingFiles(500);
        const paths = files.map((f) => f.path).filter(Boolean).join("\n");
        if (!paths) {
            showToast(TOAST_STATUS.WARNING, "No paths found");
            return;
        }
        await navigator.clipboard.writeText(paths);
        showToast(TOAST_STATUS.SUCCESS, `Copied ${files.length} path(s)`);
    } catch (err) {
        showToast(TOAST_STATUS.ERROR, "Copy failed");
    }
}

async function exportMatchingCsv() {
    if (lastFetchTotal === 0) {
        showToast(TOAST_STATUS.WARNING, "No results to export");
        return;
    }
    showToast(TOAST_STATUS.INFO, "Building CSV…");
    try {
        const files = await fetchAllMatchingFiles(500);
        const blob = new Blob([filesToCsv(files)], { type: "text/csv;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        const ipPart = investigatorQuery?.ip || getFilterValue("filterIp") || "search";
        a.href = url;
        a.download = `pcaptain-${ipPart}-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        showToast(TOAST_STATUS.SUCCESS, `Downloaded CSV (${files.length} row(s))`);
    } catch (err) {
        showToast(TOAST_STATUS.ERROR, "CSV export failed");
    }
}

function copyWiresharkCommand() {
    const path = currentFiles[0]?.path;
    if (!path) {
        showToast(TOAST_STATUS.WARNING, "No files on the current page");
        return;
    }
    const escaped = path.replace(/"/g, '\\"');
    const cmd = `wireshark "${escaped}"`;
    navigator.clipboard.writeText(cmd).then(() => {
        showToast(TOAST_STATUS.SUCCESS, "Copied Wireshark command (first file on this page)");
    }).catch(() => {
        showToast(TOAST_STATUS.ERROR, "Copy failed");
    });
}

function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

function buildWiresharkBat(paths) {
    const lines = ["@echo off", "REM PCAPtain — open captures in Wireshark"];
    for (const p of paths) {
        lines.push(`start "" wireshark "${p.replace(/"/g, '""')}"`);
    }
    return lines.join("\r\n");
}

function buildWiresharkSh(paths) {
    const lines = ["#!/bin/sh", "# PCAPtain — open captures in Wireshark"];
    for (const p of paths) {
        lines.push(`wireshark "${p.replace(/"/g, '\\"')}" &`);
    }
    return lines.join("\n");
}

async function exportWiresharkBatch() {
    if (lastFetchTotal === 0) {
        showToast(TOAST_STATUS.WARNING, "No results");
        return;
    }
    showToast(TOAST_STATUS.INFO, "Fetching file list…");
    try {
        const files = await fetchAllMatchingFiles(50);
        const paths = files.map((f) => f.path).filter(Boolean);
        if (!paths.length) {
            showToast(TOAST_STATUS.WARNING, "No paths found");
            return;
        }
        const isWin = navigator.platform.toLowerCase().includes("win");
        if (isWin) {
            downloadBlob("open-wireshark.bat", buildWiresharkBat(paths), "text/plain");
        } else {
            downloadBlob("open-wireshark.sh", buildWiresharkSh(paths), "text/plain");
        }
        showToast(TOAST_STATUS.SUCCESS, `Downloaded script for ${paths.length} file(s)`);
    } catch (err) {
        showToast(TOAST_STATUS.ERROR, "Failed to build script");
    }
}

async function refreshNewIpBanner() {
    const banner = document.getElementById("newIpBanner");
    if (!banner) return;
    try {
        const res = await axios.get(SERVER + API_PATH.CATALOG_NEW_IPS_PATH);
        if (res.data?.is_first_baseline) {
            banner.classList.add("hidden");
            return;
        }
        const ips = res.data?.new_ips || res.data?.ips || [];
        const count = Array.isArray(ips) ? ips.length : res.data?.new_ip_count ?? 0;
        if (!count) {
            banner.classList.add("hidden");
            banner.innerHTML = "";
            return;
        }
        const sample = ips.slice(0, 8).join(", ");
        const more = count > 8 ? ` … (+${count - 8})` : "";
        banner.innerHTML =
            `<strong>New IPs since last scan (${count}):</strong> ${sample}${more} ` +
            `<a href="/ops">Ops</a>`;
        banner.classList.remove("hidden");
    } catch (_) {
        banner.classList.add("hidden");
    }
}

window.pcaptainSearch = {
    runIpInvestigation,
    copyAllMatchingPaths,
    exportMatchingCsv,
    copyWiresharkCommand,
    exportWiresharkBatch
};

// Pagination for search results
function updatePaginationControls(totalItems) {
    const container = document.getElementById("paginationContainer");
    if (!container) return;

    container.innerHTML = "";

    if (totalItems === 0) return;

    const totalPages = Math.ceil(totalItems / itemsPerPage);

    const buttonsGroup = document.createElement("div");
    buttonsGroup.className = "pagination-buttons";

    const createBtn = (text, pageNum, isActive = false, isDisabled = false) => {
        const btn = document.createElement("button");
        btn.innerHTML = text; // Use innerHTML for arrows
        btn.className = "page-btn";
        if (isActive) btn.classList.add("active");
        if (isDisabled) btn.disabled = true;

        if (!isDisabled && !isActive && pageNum !== null) {
            btn.addEventListener("click", () => {
                currentPage = pageNum;
                fetchFiles();
            });
        }
        buttonsGroup.appendChild(btn);
    };

    const createEllipsis = () => {
        const span = document.createElement("span");
        span.className = "pagination-ellipsis";
        span.innerText = "...";
        buttonsGroup.appendChild(span);
    };

    // previouis button
    createBtn(`<i class="fa fa-chevron-left"></i>`, currentPage - 1, false, currentPage === 1);

    const maxVisibleButtons = 5; // How many numbered buttons to show max

    if (totalPages <= 7) {
        for (let i = 1; i <= totalPages; i++) {
            createBtn(i, i, i === currentPage);
        }
    } else {
        // Always show first page
        createBtn(1, 1, 1 === currentPage);

        // If current is far from start
        if (currentPage > 4) {
            createEllipsis();
        }

        // Neighbors Logic
        let start = Math.max(2, currentPage - 1);
        let end = Math.min(totalPages - 1, currentPage + 1);

        // Adjust if at the very start or end
        if (currentPage <= 4) {
            end = 5;
        } else if (currentPage >= totalPages - 3) {
            start = totalPages - 4;
        }

        for (let i = start; i <= end; i++) {
            createBtn(i, i, i === currentPage);
        }

        // Logic: if current is far from end
        if (currentPage < totalPages - 3) {
            createEllipsis();
        }

        // Always show last page
        createBtn(totalPages, totalPages, totalPages === currentPage);
    }

    // next button
    createBtn(`<i class="fa fa-chevron-right"></i>`, currentPage + 1, false, currentPage === totalPages);

    // Drop down of pages on the right side
    const infoGroup = document.createElement("div");
    infoGroup.className = "pagination-info";

    const labelPage = document.createElement("span");
    labelPage.innerText = "Page";
    infoGroup.appendChild(labelPage);

    const select = document.createElement("select");
    select.className = "page-select";

    for (let i = 1; i <= totalPages; i++) {
        const option = document.createElement("option");
        option.value = i;
        option.text = i;
        if (i === currentPage) option.selected = true;
        select.appendChild(option);
    }

    select.addEventListener("change", (e) => {
        currentPage = parseInt(e.target.value);
        fetchFiles();
    });
    infoGroup.appendChild(select);

    const labelTotal = document.createElement("span");
    labelTotal.innerText = `of ${totalPages}`;
    infoGroup.appendChild(labelTotal)

    container.appendChild(buttonsGroup);
    container.appendChild(infoGroup);
}

function formatDate(timestamp) {
    if (!timestamp) return "N/A";
    const date = new window.Date(parseFloat(timestamp) * 1000);
    return date.toLocaleString();
}

// --- NAMED EVENT HANDLERS ---
function handleInfoButtonClick(e) {
    e.stopPropagation();
    const index = e.target.id.split('-')[1];
    const file = currentFiles[index];
    openInfoModal(file, e);
}

function handleCopyAllPaths() {
    const paths = currentFiles.map(file => file.path).join('\n');
    navigator.clipboard.writeText(paths).then(() => {
        showToast(TOAST_STATUS.SUCCESS, "All paths copied to clipboard");
    }).catch(err => {
        showToast(TOAST_STATUS.ERROR, "Failed to copy paths");
    });
}

function handleCopyPathClick(e) {
    if (!e.target.classList.contains('copy-path-btn')) return;
    e.stopPropagation();
    const path = e.target.getAttribute('data-path');
    navigator.clipboard.writeText(path).then(() => {
        showToast(TOAST_STATUS.SUCCESS, "Path copied to clipboard");
    }).catch(err => {
        showToast(TOAST_STATUS.ERROR, "Failed to copy path");
    });
}


// --- ATTACH STATIC LISTENERS ONCE ---
document.addEventListener("DOMContentLoaded", () => {
    const copyAllBtn = document.getElementById("copyAllPathsBtn");
    if (copyAllBtn) {
        copyAllBtn.addEventListener("click", handleCopyAllPaths);
    }
    wireFastScanOptionToggles(SEARCH_FAST_IDS);
    const saved = loadFastScanPrefs();
    if (saved && cachedScanConfig) {
        updateFastScanSummary(SEARCH_FAST_IDS, cachedScanConfig);
    }
    loadScanConfigTooltip();
    checkScanStateOnReady();
});

async function checkScanStateOnReady() {
    try {
        const apiResponse = await axios.get(SERVER + API_PATH.SCAN_STATUS_PATH);
        if (!apiResponse || !apiResponse.data) return;
        const state = apiResponse.data.state;

        const spinner = document.getElementById("spinnerScanBtn");
        const scanBtn = document.getElementById("scanBtn");
        const cancelBtn = document.getElementById("cancelScanBtn");

        if (state === SERVER_SCANNING_FILE_STATUS.RUNNING) {
            if (spinner) {
                spinner.classList.remove("spinner-scan-hidden");
                spinner.classList.add("spinner-scan-visible");
            }
            if (scanBtn) scanBtn.style.display = "none";
            if (cancelBtn) cancelBtn.classList.remove("hidden");

            // Set scan_state and start interval polling
            scan_state = true;
            manageScanState();
        } else {
            if (spinner) {
                spinner.classList.add("spinner-scan-hidden");
                spinner.classList.remove("spinner-scan-visible");
            }
            if (scanBtn) scanBtn.style.display = "inline-block";
            if (cancelBtn) cancelBtn.classList.add("hidden");
        }
    } catch (err) {
        console.error("Failed to fetch scan state:", err);
    }
}

function getScanModeBadgeHtml(file) {
    const scanModeRaw = (file.scan_mode || "").toLowerCase();
    const isQuick = scanModeRaw === "quick";
    const isFast = scanModeRaw === "fast";
    const pebcValue =
        isQuick && file.pebc !== undefined && file.pebc !== null && String(file.pebc).trim() !== ""
            ? String(file.pebc).trim()
            : "N/A";

    let tooltipText = "Full Scan";
    let badgeClasses = "scan-mode-icon text-green-600";
    let iconHtml = `<span class="scan-mode-icon scan-mode-icon-full" aria-hidden="true">✓</span>`;

    if (isQuick) {
        tooltipText = `Quick Scan (${pebcValue})`;
        badgeClasses = "scan-mode-icon text-yellow-600";
        iconHtml = `<span class="scan-mode-icon scan-mode-icon-quick" aria-hidden="true">⚡</span>`;
    } else if (isFast) {
        tooltipText = "Fast Scan";
        badgeClasses = "scan-mode-icon";
        iconHtml = `<span class="scan-mode-icon scan-mode-icon-fast" aria-hidden="true">
                        <i class="fa fa-rocket"></i>
                    </span>`;
    }

    return `
        <span class="${badgeClasses}" title="${tooltipText}" aria-label="${tooltipText}">
            ${iconHtml}
        </span>
    `;
}

function parseSearchShorthand(raw) {
    // Supports: "sip !tcp !udp", "sip, !tcp", multiple spaces
    const s = (raw || "").trim();
    if (!s) return { include: [], exclude: [] };

    const tokens = s
        .split(/[\s,]+/g)
        .map(t => t.trim())
        .filter(Boolean);

    const include = [];
    const exclude = [];

    for (const t of tokens) {
        if (t.startsWith("!")) {
            const v = t.slice(1).trim();
            if (v) exclude.push(v);
        } else {
            include.push(t);
        }
    }

    const dedupCaseInsensitive = (items) => {
        const uniqueItems = [];
        const seenNormalized = new Set();

        for (const item of items) {
            const normalizedKey = item.toLowerCase();

            // Skip empty strings and anything we've already seen
            if (!normalizedKey || seenNormalized.has(normalizedKey)) continue;

            seenNormalized.add(normalizedKey);
            uniqueItems.push(item);
        }

        return uniqueItems;
    };

    return { include: dedupCaseInsensitive(include), exclude: dedupCaseInsensitive(exclude) };
}

function toTsharkDisplayFilterFromShorthand(raw) {
    const { include, exclude } = parseSearchShorthand(raw);

    // If user only types "!tcp" (no include), treat as "not tcp"
    const includeExpr = include.length
        ? include.map(p => `(${p})`).join(" or ")
        : "";

    const excludeExpr = exclude.length
        ? exclude.map(p => `(${p})`).join(" or ")
        : "";

    if (includeExpr && excludeExpr) {
        return `((${includeExpr}) and not (${excludeExpr}))`;
    }
    if (includeExpr) {
        return `(${includeExpr})`;
    }
    if (excludeExpr) {
        return `(not (${excludeExpr}))`;
    }
    return "";
}

function buildDownloadUrlWithDisplayFilter(file) {
    const input = document.getElementById("searchInput");
    const raw = (input ? input.value : "").trim();

    // No query => download original
    if (!raw) return file.download_url;

    const filter = toTsharkDisplayFilterFromShorthand(raw);
    // If convert somehow empty => fallback original
    if (!filter) return file.download_url;

    const params = new URLSearchParams();
    params.set("filter", filter);
    return `${file.download_url}?${params.toString()}`;
}


function renderTable(files) {
    const tbody = document.getElementById('resultBody');
    tbody.innerHTML = '';

    if (!files || files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No result found</td></tr>';
        return;
    }

    files.forEach((file, index) => {
        const tr = document.createElement('tr');

        const btnId = `infoBtn-${index}`;

        // Updated extra info column
        tr.innerHTML = `
            <td data-label="Filename">
                <a href="${buildDownloadUrlWithDisplayFilter(file)}" class="file-link" download>
                    ${file.filename}
                </a>
            </td>
            <td data-label="Info"> 
                <button id="${btnId}" class="info-btn" title="View Details">i</button>
            </td>
            <td data-label="Mode" class="mode-cell">
                ${getScanModeBadgeHtml(file)}
            </td>
            <td data-label="Path">
                ${file.path} 
                <i class="fa fa-copy copy-path-btn" data-path="${file.path}" title="Copy path"></i>
            </td>
            <td data-label="Matched">
                ${renderMatchedHTML(file)}
            </td>
            <td data-label="Size">${formatFileSize(file.size_bytes)}</td>
            <td data-label="Packet">${file.total_packets || '-'}</td>
            
        `;
        tbody.appendChild(tr);

        // Attach listener to info button immediately (no setTimeout needed)
        const btn = tr.querySelector(`#${btnId}`);
        if (btn) {
            btn.addEventListener("click", handleInfoButtonClick);
        }
    });

    // Use event delegation for dynamic copy buttons (attached once to tbody)
    tbody.addEventListener('click', handleCopyPathClick);
}

// Render matched protocols: show first two, and a (+N) hover tooltip for the rest
function renderMatchedHTML(file) {
    const matched = file.matched_protocols || [];
    if (!matched.length) return '-';

    const visibleCount = 1;
    const visible = matched
        .slice(0, visibleCount)
        .map(p => `<span class="proto-badge" title="Matched protocol">${p.toUpperCase()}</span>`)
        .join(' ');

    if (matched.length <= visibleCount) return visible;

    const remaining = matched.length - visibleCount;
    const remainingList = matched.map(p => p.toUpperCase()).join(', ').replace(/"/g, '&quot;');
    const moreHtml = `<span class="more-matched" title="${remainingList}">(+${remaining})</span>`;
    return `${visible} ${moreHtml}`;
}


function formatFileSize(bytes) {
    bytes = parseInt(bytes);
    if (!bytes || bytes === 0) return '0 Bytes';
    const units = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const size = parseFloat((bytes / Math.pow(k, i)).toFixed(2));
    return `${size} ${units[i]}`;
}
