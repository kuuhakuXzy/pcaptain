import { showToast } from "./toast-script.js";
import { SERVER, TOAST_STATUS } from "./constant.js";

export function formatDate(timestamp) {
    if (!timestamp) return "N/A";
    const date = new window.Date(parseFloat(timestamp) * 1000);
    return date.toLocaleString();
}

window.addEventListener("click", (e) => {
    const modal = document.getElementById("infoModal");
    if (!modal) return;
    if (modal.classList.contains("show") && !modal.contains(e.target)) {
        modal.classList.remove("show");
    }
});

export function openInfoModal(file, event) {
    const modal = document.getElementById("infoModal");
    const btn = event.currentTarget;
    if (!modal) return;

    document.getElementById("infoFilename").innerText = file.filename || "N/A";
    document.getElementById("infoPath").innerText = file.path || "N/A";
    document.getElementById("infoSize").innerText = (function(bytes){
        bytes = parseInt(bytes);
        if (!bytes || bytes === 0) return '0 Bytes';
        const units = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const k = 1024;
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        const size = parseFloat((bytes / Math.pow(k, i)).toFixed(2));
        return `${size} ${units[i]}`;
    })(file.size_bytes);
    document.getElementById("infoPackets").innerText = file.protocol_packet_count || 0;

    document.getElementById("infoModified").innerText = formatDate(file.last_modified);
    document.getElementById("infoScanned").innerText = formatDate(file.last_scanned);

    renderProtocolTable(file);

    const rect = event.currentTarget.getBoundingClientRect();
    const scrollTop = window.scrollY || document.documentElement.scrollTop;
    const scrollLeft = window.scrollX || document.documentElement.scrollLeft;
    modal.classList.remove("hidden");
    modal.classList.add("show");
    let left = (rect.right + scrollLeft) + 10;
    let top = (rect.top + scrollTop) - 20;
    modal.style.left = `${left}px`;
    modal.style.top = `${top}px`;
}

let currentProtocolData = [];
let allProtocolData = [];
let currentSortColumn = null;
let currentSortAscending = true;
let sortListenersAttached = false;
let searchListenerAttached = false;

function renderProtocolTable(file) {
    resetSortState();
    resetSearchInput();
    
    const tbody = document.getElementById("protocolTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    let percentMap = {};
    let countMap = {};

    if (file.protocol_percentages) {
        try {
            percentMap = JSON.parse(file.protocol_percentages);
        } catch (e) {
            console.error("Error parsing percentages:", e);
        }
    }

    if (file.protocol_counts) {
        try {
            countMap = JSON.parse(file.protocol_counts);
        } catch (e) {
            console.error("Error parsing counts:", e);
        }
    }

    if (!file.protocols) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">No protocols found</td></tr>';
        return;
    }

    const protos = file.protocols.split(" ");
    allProtocolData = protos.map(p => ({
        protocol: p,
        percent: percentMap[p] || 0,
        count: countMap[p] || 0
    }));
    currentProtocolData = [...allProtocolData];

    renderTableRows(file);
    
    if (!sortListenersAttached) {
        attachSortListeners(file);
        sortListenersAttached = true;
    }
    
    if (!searchListenerAttached) {
        attachSearchListener(file);
        searchListenerAttached = true;
    }
}

function renderTableRows(file) {
    const tbody = document.getElementById("protocolTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    currentProtocolData.forEach(data => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td>${data.protocol.toUpperCase()}</td>
            <td>${data.percent.toFixed(2)}</td>
            <td>${data.count}</td>
            <td>
                <button class="download-protocol-btn" data-protocol="${data.protocol}" title="Download ${data.protocol.toUpperCase()} packets">
                    <i class="fa fa-download"></i>
                </button>
            </td>
        `;
        tbody.appendChild(tr);

        const downloadBtn = tr.querySelector(".download-protocol-btn");
        downloadBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            const protocol = downloadBtn.getAttribute("data-protocol");
            showToast(TOAST_STATUS.INFO, `Preparing download for ${protocol.toUpperCase()}...`);
            const fileHash = file.download_url.split("/").pop();
            const downloadUrl = `${SERVER}pcaps/download/${fileHash}/filter?protocol=${protocol}`;
            window.location.href = downloadUrl;
        });
    });
}

function attachSortListeners(file) {
    const sortHeaders = document.querySelectorAll("th.sortable");
    sortHeaders.forEach(th => {
        // Remove any existing listener first to prevent duplicates
        th.removeEventListener("click", th._sortClickHandler);
        
        // Create and store the handler
        th._sortClickHandler = (e) => {
            e.stopPropagation();
            const sortColumn = th.getAttribute("data-sort");
            
            if (currentSortColumn === sortColumn) {
                currentSortAscending = !currentSortAscending;
            } else {
                currentSortColumn = sortColumn;
                currentSortAscending = true;
            }

            sortProtocolData(sortColumn, currentSortAscending);
            renderTableRows(file);
            updateSortIcons(sortColumn, currentSortAscending);
        };
        
        th.addEventListener("click", th._sortClickHandler);
    });
}

function sortProtocolData(column, ascending) {
    currentProtocolData.sort((a, b) => {
        let valA = a[column];
        let valB = b[column];

        if (column === "protocol") {
            valA = valA.toLowerCase();
            valB = valB.toLowerCase();
            return ascending ? valA.localeCompare(valB) : valB.localeCompare(valA);
        } else {
            return ascending ? valA - valB : valB - valA;
        }
    });
}

function updateSortIcons(activeColumn, ascending) {
    const sortHeaders = document.querySelectorAll("th.sortable");
    sortHeaders.forEach(th => {
        const icon = th.querySelector("i");
        const column = th.getAttribute("data-sort");
        
        if (column === activeColumn) {
            icon.className = ascending ? "fa fa-sort-asc" : "fa fa-sort-desc";
        } else {
            icon.className = "fa fa-sort";
        }
    });
}

function attachSearchListener(file) {
    const searchInput = document.getElementById("protocolSearchInput");
    if (!searchInput) return;
    
    searchInput.removeEventListener("input", searchInput._searchHandler);
    
    searchInput._searchHandler = (e) => {
        const query = e.target.value.toLowerCase().trim();
        
        if (query === "") {
            currentProtocolData = [...allProtocolData];
        } else {
            currentProtocolData = allProtocolData.filter(p => 
                p.protocol.toLowerCase().includes(query)
            );
        }
        
        // Re-apply current sort if any
        if (currentSortColumn) {
            sortProtocolData(currentSortColumn, currentSortAscending);
        }
        
        renderTableRows(file);
    };
    
    searchInput.addEventListener("input", searchInput._searchHandler);
}

function resetSearchInput() {
    const searchInput = document.getElementById("protocolSearchInput");
    if (searchInput) {
        searchInput.value = "";
    }
    searchListenerAttached = false;
}

function resetSortState() {
    currentSortColumn = null;
    currentSortAscending = true;
    currentProtocolData = [];
    allProtocolData = [];
    sortListenersAttached = false;
    
    // Reset all sort icons to default
    const sortHeaders = document.querySelectorAll("th.sortable");
    sortHeaders.forEach(th => {
        const icon = th.querySelector("i");
        if (icon) {
            icon.className = "fa fa-sort";
        }
    });
}
