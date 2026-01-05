import { showToast } from "./toast-script.js";
import {
    API_PATH,
    CHECK_SCAN_FILES_STATUS_INTERVAL,
    MIN_QUERY_LENGTH,
    SERVER_HEALTH_CHECK_INTERVAL,
    SERVER_SCANNING_FILE_STATUS,
    TOAST_STATUS
} from "./constant.js";


// --- STATE MANAGEMENT ---
let currentPage = 1;
let itemsPerPage = 5;
let currentSortBy = "filename";
let currentDescending = false;

const SERVER = new URL(`http://${window.APP_CONFIG.BASE_URL}:${window.APP_CONFIG.BASE_PORT}`).href;

// --- UI HELPERS ---
function displaySearchLoadingSpinner() {
    const spinner = document.getElementById("spinnerSearchBtn");
    const searchBtn = document.getElementById("searchBtn");
    if(spinner) {
        spinner.classList.remove("spinner-search-hidden");
        spinner.classList.add("spinner-search-visible");
    }
    if(searchBtn) searchBtn.style.display = "none";
}

function disappearSearchLoadingSpinner() {
    const spinner = document.getElementById("spinnerSearchBtn");
    const searchBtn = document.getElementById("searchBtn");
    if(spinner) {
        spinner.classList.add("spinner-search-hidden");
        spinner.classList.remove("spinner-search-visible");
    }
    if(searchBtn) searchBtn.style.display = "inline-block";
}

document.getElementById("searchBtn").addEventListener("click", () => {
    currentPage = 1; // Reset to page 1 on new search
    fetchFiles();
});

const searchInput = document.getElementById("searchInput");
searchInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        currentPage = 1; // Reset to page 1 on new search
        hideSuggestion();
        fetchFiles();
    }
});

const sortBySelect = document.getElementById("sortBy");
const sortOrderSelect = document.getElementById("sortOrder");
const limitSelect = document.getElementById("limitSelect");

if (limitSelect) limitSelect.value = "5"; 
if (sortBySelect) sortBySelect.value = "filename";    
if (sortOrderSelect) sortOrderSelect.value = "false";

// Listen to user's items per page
if (limitSelect) {
    limitSelect.addEventListener("change", (e) => {
        itemsPerPage = parseInt(e.target.value);
        currentPage = 1; 
        fetchFiles();
    });
}

if (sortBySelect) {
    sortBySelect.addEventListener("change", (e) => {
        currentSortBy = e.target.value;
        currentPage = 1; 
        fetchFiles();
    });
}

if (sortOrderSelect) {
    sortOrderSelect.addEventListener("change", (e) => {
        currentDescending = e.target.value === "true";
        currentPage = 1; 
        fetchFiles();
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
    if(spinner) {
        spinner.classList.remove("spinner-scan-hidden");
        spinner.classList.add("spinner-scan-visible");
    }
    if(scanBtn) scanBtn.style.display = "none";
}

function disappearScanLoadingSpinner() {
    const spinner = document.getElementById("spinnerScanBtn");
    const scanBtn = document.getElementById("scanBtn");
    if(spinner) {
        spinner.classList.add("spinner-scan-hidden");
        spinner.classList.remove("spinner-scan-visible");
    }
    if(scanBtn) scanBtn.style.display = "inline-block";
}

document.getElementById("scanAllBtn").addEventListener("click", async () => {
    const scanModal = document.getElementById("scanModal");
    scanModal.classList.add("hidden");
    await scanFiles();
});

// Cancel scan button
document.getElementById("cancelScanBtn").addEventListener("click", async () => {
    try {
        const apiResponse = await axios.post(SERVER + API_PATH.CANCEL_SCAN_PATH);
        if (apiResponse && apiResponse.data) {
            showToast(TOAST_STATUS.INFO, "Scan cancellation requested");
        }
    } catch (err) {
        console.error("Error cancelling scan:", err);
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
            statusSignal.innerHTML = `<i class="fa fa-circle"></i><span>Server Error</span>`;
        }
    } catch (err) {
        console.log("Health check failed", err);
        statusSignal.innerHTML = `<i class="fa fa-circle"></i><span>Server Error</span>`;
    }
}
serverHealthCheck();
setInterval(serverHealthCheck, SERVER_HEALTH_CHECK_INTERVAL);

async function scanFiles() {
    displayScanLoadingSpinner();
    const cancelBtn = document.getElementById("cancelScanBtn");
    
    try {
        const apiResponse = await axios.post(SERVER + API_PATH.PCAP_REINDEX_PATH);
        if (!apiResponse) {
            disappearScanLoadingSpinner();
            return showToast(TOAST_STATUS.ERROR, "Failed to trigger scan");
        }
        
        // Show cancel button when scan starts
        if (cancelBtn) cancelBtn.classList.remove("hidden");
        
        const timer = setInterval(async () => {
            try {
                const apiResponse = await axios.get(SERVER + API_PATH.SCAN_STATUS_PATH);
                const status = apiResponse.data.state;
                if (status === SERVER_SCANNING_FILE_STATUS.COMPLETED ||
                    status === SERVER_SCANNING_FILE_STATUS.IDLE
                ) {
                    disappearScanLoadingSpinner();
                    if (cancelBtn) cancelBtn.classList.add("hidden");
                    clearInterval(timer);
                    showToast(TOAST_STATUS.SUCCESS, "Scan completed successfully");
                } else if (status === SERVER_SCANNING_FILE_STATUS.FAILED) {
                    disappearScanLoadingSpinner();
                    if (cancelBtn) cancelBtn.classList.add("hidden");
                    clearInterval(timer);
                    showToast(TOAST_STATUS.ERROR, "Scan failed");
                }
            } catch (err) {
                disappearScanLoadingSpinner();
                if (cancelBtn) cancelBtn.classList.add("hidden");
                clearInterval(timer);
            }
        }, CHECK_SCAN_FILES_STATUS_INTERVAL);
    } catch (err) {
        disappearScanLoadingSpinner();
        if (cancelBtn) cancelBtn.classList.add("hidden");
        console.error("API error: ", err);
        showToast(TOAST_STATUS.ERROR, "Error triggering scan");
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
                    protocol: search,
                    page: currentPage,
                    limit: itemsPerPage,
                    sort_by: currentSortBy,
                    descending: currentDescending
                }
            }
        );

        disappearSearchLoadingSpinner();

        if (!apiResponse || !apiResponse.data) {
            showToast(TOAST_STATUS.ERROR, "Failed to get response");
            return;
        }

        // Object response { total, page, data: [] }
        const responseData = apiResponse.data;
        const files = responseData.data; 
        const totalItems = responseData.total;

        renderTable(files);
        updatePaginationControls(totalItems);

    } catch (err) {
        disappearSearchLoadingSpinner();
        console.error("API error: ", err);
        showToast(TOAST_STATUS.ERROR, "Error while searching files");
    }
}

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

function renderTable(files) {
    const tbody = document.getElementById('resultBody');
    tbody.innerHTML = '';

    if (!files || files.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No result found</td></tr>';
        return;
    }

    files.forEach((file, index) => {
        const tr = document.createElement('tr');
        
        const btnId = `infoBtn-${index}`;

        // Updated extra info column
        tr.innerHTML = `
            <td data-label="Filename">
                <a href="${file.download_url}" class="file-link" download>
                    ${file.filename}
                </a>
            </td>
            <td data-label="Info"> 
                <button id="${btnId}" class="info-btn" title="View Details">i</button>
            </td>
            <td data-label="Path">${file.path}</td>
            <td data-label="Size">${formatFileSize(file.size_bytes)}</td>
            <td data-label="Packet">${file.protocol_packet_count}</td>
            
        `;
        tbody.appendChild(tr);

        setTimeout(() => {
            const btn = document.getElementById(btnId);
            if(btn){
                btn.addEventListener("click", (e) => {
                    e.stopPropagation(); 
                    openInfoModal(file, e);
                });
            }
        }, 0);
    });
}


window.addEventListener("click", (e) => {
    const modal = document.getElementById("infoModal");
    
    if (modal.classList.contains("show") && !modal.contains(e.target)) {
        modal.classList.remove("show");
    }
});

// Pop up modal for each pcap file
function openInfoModal(file, event) {
    const modal = document.getElementById("infoModal");
    const btn = event.currentTarget;

    document.getElementById("infoFilename").innerText = file.filename || "N/A";
    document.getElementById("infoPath").innerText = file.path || "N/A";
    document.getElementById("infoSize").innerText = formatFileSize(file.size_bytes);
    document.getElementById("infoPackets").innerText = file.protocol_packet_count || 0;

    document.getElementById("infoModified").innerText = formatDate(file.last_modified);
    document.getElementById("infoScanned").innerText = formatDate(file.last_scanned);

    // Fill all protocols
    const protoContainer = document.getElementById("infoProtocols");
    protoContainer.innerHTML = "";

    let percentMap = {};

    if (file.protocol_percentages) {

        try {

            percentMap = JSON.parse(file.protocol_percentages);

        } catch (e) {

            console.error("Error parsing percentages:", e);

        }

    }
    
    if (file.protocols) {
        const protos = file.protocols.split(","); 
        protos.forEach(p => {
            const badge = document.createElement("span");
            badge.className = "proto-badge";
            
            const pct = percentMap[p] || 0;
            badge.innerText = `${p.toUpperCase()} (${pct}%)`;
            
            badge.style.cursor = "pointer";
            badge.title = `Click to download only ${p.toUpperCase()} packets`;

            badge.addEventListener("click", async (e) => {
                e.stopPropagation(); 
                
                showToast(TOAST_STATUS.INFO, `Preparing download for ${p.toUpperCase()}...`);
                
                const fileHash = file.download_url.split("/").pop(); 
                const downloadUrl = `${SERVER}pcaps/download/${fileHash}/filter?protocol=${p}`;
                
                window.location.href = downloadUrl;
            });

            protoContainer.appendChild(badge);
        });
    }

    // Locate the modal next to the button
    const rect = btn.getBoundingClientRect();
    
    const scrollTop = window.scrollY || document.documentElement.scrollTop;
    const scrollLeft = window.scrollX || document.documentElement.scrollLeft;

    modal.classList.remove("hidden"); 
    modal.classList.add("show");
    
    let left = (rect.right + scrollLeft) + 10; 
    let top = (rect.top + scrollTop) - 20;

    modal.style.left = `${left}px`;
    modal.style.top = `${top}px`;
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