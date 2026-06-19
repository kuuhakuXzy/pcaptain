import { SERVER, API_PATH, TOAST_STATUS } from "../constant.js";
import { showToast } from "../toast-script.js";

const loadingIndicator = document.getElementById("loadingIndicator");
const errorMessage = document.getElementById("errorMessage");
const operationsContent = document.getElementById("operationsContent");
const refreshBtn = document.getElementById("refreshBtn");
const lastUpdatedEl = document.getElementById("lastUpdated");
const autoRefreshLabel = document.getElementById("autoRefreshLabel");

let pollTimer = null;
let currentScanMode = "fast";
let scanModeApplyInFlight = false;

document.addEventListener("DOMContentLoaded", () => {
    loadOperations();
    refreshBtn.addEventListener("click", () => loadOperations());
});

async function loadOperations() {
    showLoading();
    refreshBtn.disabled = true;

    try {
        const response = await axios.get(`${SERVER}${API_PATH.DASHBOARD_OPERATIONS_PATH}`);
        renderOperations(response.data);
        scheduleRefresh(response.data);
    } catch (error) {
        console.error("Error loading operations dashboard:", error);
        showError(error.response?.data?.detail || error.response?.data?.error || "Failed to load operations data");
        scheduleRefresh(null);
    } finally {
        refreshBtn.disabled = false;
    }
}

function scheduleRefresh(data) {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }

    const scanRunning = data?.scan?.state === "running";
    const backfillRunning = data?.backfill?.state === "running";
    const rebuildRunning = data?.rebuild_searchindex?.state === "running";
    const active = scanRunning || backfillRunning || rebuildRunning;
    const intervalMs = active ? 15000 : 60000;

    autoRefreshLabel.textContent = active ? "every 15s (job running)" : "every 1 min";
    pollTimer = setInterval(loadOperations, intervalMs);
}

function showLoading() {
    loadingIndicator.classList.remove("hidden");
    errorMessage.classList.add("hidden");
    operationsContent.classList.add("hidden");
}

function showError(message) {
    loadingIndicator.classList.add("hidden");
    operationsContent.classList.add("hidden");
    errorMessage.classList.remove("hidden");
    errorMessage.textContent = message;
}

function showContent() {
    loadingIndicator.classList.add("hidden");
    errorMessage.classList.add("hidden");
    operationsContent.classList.remove("hidden");
}

function renderOperations(data) {
    showContent();

    const date = new Date(data.generated_at * 1000);
    lastUpdatedEl.textContent = date.toLocaleString();

    renderStatusGrid(data);
    renderJobsPanel(data);
    renderAlertsPanel(data);
    renderConfigPanel(data);
    renderPathsPanel(data);
    renderRecentAlerts(data);
}

function renderStatusGrid(data) {
    const grid = document.getElementById("statusGrid");
    const health = data.health || {};
    const index = data.index || {};
    const alerts = data.alerts || {};
    const scanState = data.scan?.state || "unknown";

    const cards = [
        {
            label: "API",
            value: health.api === "ok" ? "Online" : "Down",
            detail: "Backend reachable",
            tone: health.api === "ok" ? "ok" : "error",
        },
        {
            label: "Redis",
            value: health.redis === "ok" ? "Connected" : "Error",
            detail: "Index store",
            tone: health.redis === "ok" ? "ok" : "error",
        },
        {
            label: "Scan",
            value: formatState(scanState),
            detail: data.scan?.message || "—",
            tone: stateTone(scanState),
        },
        {
            label: "Indexed Files",
            value: formatNumber(index.total_files || 0),
            detail: formatBytes(index.total_size_bytes || 0),
            tone: "info",
        },
        {
            label: "Alerted Files",
            value: formatNumber(alerts.files_with_alerts || 0),
            detail: `${formatNumber(alerts.alert_events || 0)} alert events`,
            tone: (alerts.files_with_alerts || 0) > 0 ? "warn" : "ok",
        },
        {
            label: "Analytics Cache",
            value: formatState(data.dashboard_cache?.status || "missing"),
            detail: cacheAgeLabel(data.dashboard_cache?.generated_at),
            tone: data.dashboard_cache?.status === "processing" ? "warn" : "info",
        },
    ];

    grid.innerHTML = cards.map((card) => `
        <div class="status-card ${card.tone}">
            <div class="status-label">${card.label}</div>
            <div class="status-value">${card.value}</div>
            <div class="status-detail">${escapeHtml(card.detail)}</div>
        </div>
    `).join("");
}

function renderJobsPanel(data) {
    const panel = document.getElementById("jobsPanel");
    const index = data.index || {};
    const lastRun = data.scan?.last_run;

    const jobs = [
        {
            name: "PCAP Scan / Reindex",
            state: data.scan?.state,
            message: data.scan?.message,
            extra: lastRun
                ? `Last run: ${formatNumber(lastRun.total_files || 0)} scanned · ${formatNumber(lastRun.fast_skipped || 0)} fast-skipped · ${formatNumber(lastRun.indexed_files || 0)} newly indexed · ${formatLastRunTime(lastRun.finished_at)}`
                : (data.scan?.indexed_files != null
                    ? `${formatNumber(data.scan.indexed_files)} files indexed this run`
                    : null),
        },
        {
            name: "Backfill Total Packets",
            state: data.backfill?.state,
            message: data.backfill?.message,
            extra: progressLabel(data.backfill),
        },
        {
            name: "Rebuild Search Index",
            state: data.rebuild_searchindex?.state,
            message: data.rebuild_searchindex?.message,
            extra: progressLabel(data.rebuild_searchindex),
        },
    ];

    panel.innerHTML = `
        <div class="kv-table-wrap">
            <table class="kv-table">
                <tr><td>Path fingerprint entries</td><td>${formatNumber(index.path_index_entries || 0)}</td></tr>
            </table>
        </div>
        ${jobs.map((job) => `
            <div class="job-card">
                <div class="job-header">
                    <span class="job-name">${job.name}</span>
                    <span class="badge ${job.state || "idle"}">${formatState(job.state)}</span>
                </div>
                <div class="job-message">${escapeHtml(job.message || "—")}</div>
                ${job.extra ? `<div class="job-message">${escapeHtml(job.extra)}</div>` : ""}
            </div>
        `).join("")}
    `;
}

function renderAlertsPanel(data) {
    const panel = document.getElementById("alertsPanel");
    const alerts = data.alerts || {};
    const bySeverity = alerts.by_severity || {};
    const totalEvents = alerts.alert_events || 0;
    const severities = ["high", "medium", "low"];

    const bars = severities.map((sev) => {
        const count = bySeverity[sev] || 0;
        const pct = totalEvents ? Math.round((count / totalEvents) * 100) : 0;
        return `
            <div class="severity-row">
                <span>${sev}</span>
                <div class="severity-bar-track">
                    <div class="severity-bar-fill ${sev}" style="width:${pct}%"></div>
                </div>
                <span>${count}</span>
            </div>
        `;
    }).join("");

    panel.innerHTML = `
        <table class="kv-table">
            <tr><td>Files with alerts</td><td>${formatNumber(alerts.files_with_alerts || 0)}</td></tr>
            <tr><td>Alert rules</td><td>${alerts.enabled_rules || 0} enabled / ${alerts.total_rules || 0} total</td></tr>
        </table>
        <div class="severity-bars">${bars}</div>
    `;
}

function renderConfigPanel(data) {
    const cfg = data.scan_config || {};
    currentScanMode = cfg.scan_mode || currentScanMode;

    const rows = [
        ["Scan mode (active)", cfg.scan_mode],
        ["Max parallel scans", cfg.max_parallel_scans],
        ["Config version", cfg.config_version],
        ["Sample segments", cfg.sample_segments],
        ["PEBC (quick)", cfg.pebc ?? "—"],
        ["Min file size (quick)", cfg.min_file_size ?? "—"],
    ];

    document.getElementById("configPanel").innerHTML = `
        <table class="kv-table">
            ${rows.map(([label, value]) => `
                <tr><td>${label}</td><td>${escapeHtml(String(value ?? "—"))}</td></tr>
            `).join("")}
        </table>
    `;

    renderScanModeControl(data);
}

function renderScanModeControl(data) {
    const container = document.getElementById("scanModeControl");
    if (!container) return;

    const scanRunning = data?.scan?.state === "running";
    const modes = [
        {
            value: "full",
            label: "Full Scan",
            hint: "tshark full protocol histogram — slowest, most accurate",
        },
        {
            value: "quick",
            label: "Quick Scan",
            hint: "sample head/middle/tail — faster on large files",
        },
        {
            value: "fast",
            label: "Fast Scan",
            hint: "fastscan C++ — fastest, current default for large catalogs",
        },
    ];

    container.innerHTML = `
        <h3>Change scan mode</h3>
        <p>Applies to the next scan/reindex. Existing indexed files keep their old mode until re-scanned.</p>
        <div class="scan-mode-options">
            ${modes.map((mode) => `
                <label class="scan-mode-option">
                    <input type="radio" name="scanModeOption" value="${mode.value}" ${mode.value === currentScanMode ? "checked" : ""} ${scanRunning ? "disabled" : ""} />
                    <span class="scan-mode-option-text">
                        <strong>${mode.label}</strong>
                        <span>${mode.hint}</span>
                    </span>
                </label>
            `).join("")}
        </div>
        <div class="scan-mode-actions">
            <label>
                <input type="checkbox" id="reindexAfterScanMode" ${scanRunning ? "disabled" : ""} />
                Reindex after apply
            </label>
            <button type="button" id="applyScanModeBtn" class="btn-apply-scan-mode" ${scanRunning ? "disabled" : ""}>
                Apply scan mode
            </button>
        </div>
    `;

    document.getElementById("applyScanModeBtn")?.addEventListener("click", applyScanMode);
}

async function applyScanMode() {
    if (scanModeApplyInFlight) return;

    const selected = document.querySelector('input[name="scanModeOption"]:checked')?.value;
    if (!selected) {
        showToast(TOAST_STATUS.WARNING, "Select a scan mode");
        return;
    }

    if (selected === currentScanMode) {
        showToast(TOAST_STATUS.INFO, `Scan mode is already ${selected}`);
        return;
    }

    const reindex = document.getElementById("reindexAfterScanMode")?.checked ?? false;
    const btn = document.getElementById("applyScanModeBtn");
    scanModeApplyInFlight = true;
    if (btn) btn.disabled = true;

    try {
        const response = await axios.patch(
            `${SERVER}${API_PATH.SCAN_CONFIG_PATH}`,
            { scan_mode: selected },
            { params: { reindex } }
        );
        currentScanMode = response.data?.scan_config?.scan_mode || selected;
        showToast(TOAST_STATUS.SUCCESS, response.data?.message || "Scan mode updated");
        await loadOperations();
    } catch (error) {
        const detail = error.response?.data?.detail || error.message || "Failed to update scan mode";
        showToast(TOAST_STATUS.ERROR, typeof detail === "string" ? detail : JSON.stringify(detail));
    } finally {
        scanModeApplyInFlight = false;
        if (btn) btn.disabled = false;
    }
}

function renderPathsPanel(data) {
    const paths = data.pcap_paths || {};
    const roots = paths.root_directories || [];
    const display = paths.display_paths || [];

    document.getElementById("pathsPanel").innerHTML = `
        <table class="kv-table">
            <tr><td>Upload directory</td><td>${escapeHtml(paths.upload_directory || "—")}</td></tr>
            <tr><td>Allowed extensions</td><td>${escapeHtml((paths.allowed_extensions || []).join(", ") || "—")}</td></tr>
        </table>
        <p style="margin:12px 0 6px;font-size:12px;color:#64748b">Root directories</p>
        <ul class="path-list">
            ${roots.length ? roots.map((p, i) => `<li>${escapeHtml(display[i] || p)}</li>`).join("") : '<li class="empty-note">No paths configured</li>'}
        </ul>
    `;
}

function renderRecentAlerts(data) {
    const panel = document.getElementById("recentAlertsPanel");
    const recent = data.alerts?.recent || [];

    if (!recent.length) {
        panel.innerHTML = '<p class="empty-note">No alerted files in the index.</p>';
        return;
    }

    panel.innerHTML = `
        <table class="alert-files-table">
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Alerts</th>
                    <th>Top severity</th>
                    <th>Path</th>
                </tr>
            </thead>
            <tbody>
                ${recent.map((item) => `
                    <tr>
                        <td>${escapeHtml(item.filename || item.file_hash)}</td>
                        <td>${item.alert_count}</td>
                        <td><span class="sev-pill ${item.top_severity || "medium"}">${item.top_severity || "medium"}</span></td>
                        <td class="path-cell" title="${escapeAttr(item.path || "")}">${escapeHtml(item.path || "—")}</td>
                    </tr>
                `).join("")}
            </tbody>
        </table>
    `;
}

function progressLabel(job) {
    if (!job || job.total == null) return null;
    if (!job.total) return null;
    const processed = job.processed ?? job.backfilled ?? 0;
    return `${formatNumber(processed)} / ${formatNumber(job.total)} processed`;
}

function cacheAgeLabel(generatedAt) {
    if (!generatedAt) return "No cached summary";
    const ageSec = Math.max(0, Math.floor(Date.now() / 1000 - generatedAt));
    if (ageSec < 60) return `Updated ${ageSec}s ago`;
    if (ageSec < 3600) return `Updated ${Math.floor(ageSec / 60)}m ago`;
    return `Updated ${Math.floor(ageSec / 3600)}h ago`;
}

function formatLastRunTime(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleString();
}

function formatState(state) {
    if (!state) return "Unknown";
    return String(state).replace(/_/g, " ");
}

function stateTone(state) {
    if (state === "running") return "warn";
    if (state === "failed") return "error";
    if (state === "completed") return "ok";
    return "info";
}

function formatNumber(value) {
    return Number(value || 0).toLocaleString();
}

function formatBytes(bytes) {
    const n = Number(bytes || 0);
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
    return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function escapeAttr(text) {
    return escapeHtml(text).replace(/'/g, "&#39;");
}

window.addEventListener("beforeunload", () => {
    if (pollTimer) clearInterval(pollTimer);
});
