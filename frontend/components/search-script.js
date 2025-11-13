import { showToast } from "./toast-script.js";
import {
    API_PATH,
    CHECK_SCAN_FILES_STATUS_INTERVAL,
    MIN_QUERY_LENGTH,
    SERVER_HEALTH_CHECK_INTERVAL,
    SERVER_SCANNING_FILE_STATUS,
    TOAST_STATUS
} from "./constant.js";

const SERVER = new URL(`http://${window.APP_CONFIG.BASE_URL}:${window.APP_CONFIG.BASE_PORT}`).href;

// Search function
function displaySearchLoadingSpinner() {
    const spinner = document.getElementById("spinnerSearchBtn");
    const searchBtn = document.getElementById("searchBtn");

    spinner.classList.remove("spinner-search-hidden");
    spinner.classList.add("spinner-search-visible");
    searchBtn.style.display = "none";
}

function disappearSearchLoadingSpinner() {
    const spinner = document.getElementById("spinnerSearchBtn");
    const searchBtn = document.getElementById("searchBtn");

    spinner.classList.add("spinner-search-hidden");
    spinner.classList.remove("spinner-search-visible");
    searchBtn.style.display = "inline-block";
}

document.getElementById("searchBtn").addEventListener("click", () => {
    fetchFiles();
});

const searchInput = document.getElementById("searchInput");
const suggestionBox = document.getElementById("suggestionBox");
searchInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        fetchFiles();
    }
});

// Search Suggestion
document.addEventListener("click", (e) => {
    if (!searchInput.contains(e.target) && !suggestionBox.contains(e.target)) {
        hideSuggestion();
    }
});

searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        hideSuggestion();
    } else if (e.key === "Enter") {
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

document.getElementById("searchBtn").addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        hideSuggestion();
    }
});

async function fetchSuggestion(input) {
    try {
        const apiResponse = await axios.get(
            SERVER + API_PATH.SEARCH_SUGGESTION,
            {
                params: {
                    q: input
                }
            }
        );
        if (!apiResponse) {
            showToast(TOAST_STATUS.ERROR, "Failed to fetch search suggestion")
        }
        const result = apiResponse.data;
        renderSuggestion(input, result);
    } catch (err) {
        console.log("Error while fetching search suggestion: ", err);
        showToast(TOAST_STATUS.ERROR, "Error while fetching search suggestion");
    }
}

function renderSuggestion(input, data) {
    if (!data.length) {
        hideSuggestion();
        return;
    }
    suggestionBox.innerHTML = "";
    data.forEach(item => {
        const div = document.createElement("div");
        div.className = "suggestion-item";

        // Highlight matching part
        const regex = new RegExp(`(${escapeRegExp(input)})`, "gi");
        const html = item.replace(regex, "<strong>$1</strong>");
        div.innerHTML = html;

        div.addEventListener("click", () => {
            searchInput.value = item;
            hideSuggestion();
            fetchFiles();   // auto-search
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

// Scan Popup
document.getElementById("scanBtn").addEventListener("click", () => {
    document.getElementById("scanModal").classList.remove("hidden");
});

document.getElementById("closeModalBtn").addEventListener("click", () => {
    document.getElementById("scanModal").classList.add("hidden");
});

// Scan all button
function displayScanLoadingSpinner() {
    const spinner = document.getElementById("spinnerScanBtn");
    const scanBtn = document.getElementById("scanBtn");

    spinner.classList.remove("spinner-scan-hidden");
    spinner.classList.add("spinner-scan-visible");
    scanBtn.style.display = "none";
}

function disappearScanLoadingSpinner() {
    const spinner = document.getElementById("spinnerScanBtn");
    const scanBtn = document.getElementById("scanBtn");

    spinner.classList.add("spinner-scan-hidden");
    spinner.classList.remove("spinner-scan-visible");
    scanBtn.style.display = "inline-block";
}

document.getElementById("scanAllBtn").addEventListener("click", async () => {
    const scanModal = document.getElementById("scanModal");

    scanModal.classList.add("hidden");

    await scanFiles();
});

// Handle "Choose Directory" button
document.getElementById("chooseDirBtn").addEventListener("click", () => {
    alert("Choose a specific directory...");
    document.getElementById("scanModal").classList.add("hidden");
});

async function serverHealthCheck() {
    const statusSignal = document.querySelector(".status-signal");
    if (!statusSignal) return;

    try {
        const apiResponse = await axios.get(SERVER + API_PATH.SERVER_HEALTH_CHECK_PATH);
        if (!apiResponse) {
            statusSignal.innerHTML = `
                <i class="fa fa-circle"></i>
                <span>Server Error</span>
            `;
        }
        const res = apiResponse.data.status;
        if (res !== "OK") {
            statusSignal.innerHTML = `
                <i class="fa fa-circle"></i>
                <span>Server Error</span>
            `;
        }
    } catch (err) {
        console.log("Error while checking server health: ", err);
    }
}
serverHealthCheck();
setInterval(serverHealthCheck, SERVER_HEALTH_CHECK_INTERVAL);

async function scanFiles() {
    displayScanLoadingSpinner();
    try {
        const apiResponse = await axios.post(SERVER + API_PATH.PCAP_REINDEX_PATH);
        if (!apiResponse) {
            disappearScanLoadingSpinner();
            return showToast(TOAST_STATUS.ERROR, "Failed to fetch PCAP files");
        }
        const timer = setInterval(async () => {
            try {
                const apiResponse = await axios.get(SERVER + API_PATH.SCAN_STATUS_PATH);
                const status = apiResponse.data.state;
                if (status === SERVER_SCANNING_FILE_STATUS.COMPLETED ||
                    status === SERVER_SCANNING_FILE_STATUS.IDLE
                ) {
                    disappearScanLoadingSpinner();
                    clearInterval(timer);
                    return showToast(TOAST_STATUS.SUCCESS, "Scanned PCAP files successfully");
                }
            } catch (err) {
                disappearScanLoadingSpinner();
                console.log("Error while checking the scan files status: ", err);
                clearInterval(timer);
                return showToast(TOAST_STATUS.ERROR, "Failed to check the status of scanning files");
            }
        }, CHECK_SCAN_FILES_STATUS_INTERVAL);
    } catch (err) {
        disappearScanLoadingSpinner();
        console.error("❌ API error: ", err);
    }
}

async function fetchFiles() {
    const search = document.getElementById("searchInput").value.toLowerCase().trim();
    if (!search) {
        return showToast(TOAST_STATUS.WARNING, "Please enter protocol");
    }

    try {
        displaySearchLoadingSpinner();
        const apiResponse = await axios.get(
            SERVER + API_PATH.PCAP_SEARCHING_PATH,
            {
                params: {
                    protocol: search
                }
            }
        );
        if (!apiResponse) {
            disappearSearchLoadingSpinner();
            showToast(TOAST_STATUS.ERROR, "Failed to search PCAP files by protocol");
        }

        const files = apiResponse.data;
        if (!files || files.length === 0) {
            disappearSearchLoadingSpinner();
        }
        disappearSearchLoadingSpinner();
        renderTable(files);
    } catch (err) {
        disappearSearchLoadingSpinner();
        console.error("❌ API error: ", err);
        showToast(TOAST_STATUS.ERROR, "Error while search PCAP files by protocol");
    }
}

function renderTable(files) {
    const tbody = document.getElementById('resultBody');
    tbody.innerHTML = '';

    if (!files || files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3">No result found</td></tr>';
        return;
    }

    files.forEach(file => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td data-label="Filename">
                <a 
                    href="${file.download_url}" 
                    class="file-link"
                    download
                >
                    ${file.filename}
                </a>
            </td>
            <td data-label="Path">${file.path}</td>
            <td data-label="Size">${formatFileSize(file.size_bytes)}</td>
            <td data-label="Packet">${file.protocol_packet_count}</td>
        `;
        tbody.appendChild(tr);
    });
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const units = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const k = 1024;
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const size = parseFloat((bytes / Math.pow(k, i)).toFixed(2));
    return `${size} ${units[i]}`;
}