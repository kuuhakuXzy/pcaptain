// Tyler code
import { showToast } from "./toast-script.js";
import { API_PATH, SERVER, TOAST_STATUS } from "./constant.js";

let alertRules = [];

// --- UPLOAD ---

function initUpload() {
    const zone = document.getElementById("uploadZone");
    const input = document.getElementById("uploadInput");
    const uploadBtn = document.getElementById("uploadBtn");

    if (!zone || !input) return;

    zone.addEventListener("click", () => input.click());
    uploadBtn?.addEventListener("click", () => input.click());

    zone.addEventListener("dragover", (e) => {
        e.preventDefault();
        zone.classList.add("dragover");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
    zone.addEventListener("drop", (e) => {
        e.preventDefault();
        zone.classList.remove("dragover");
        const file = e.dataTransfer?.files?.[0];
        if (file) uploadFile(file);
    });

    input.addEventListener("change", () => {
        const file = input.files?.[0];
        if (file) uploadFile(file);
        input.value = "";
    });
}

async function uploadFile(file) {
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (!["pcap", "pcapng", "cap"].includes(ext)) {
        showToast(TOAST_STATUS.ERROR, "Only .pcap, .pcapng, .cap files are allowed");
        return;
    }

    const progress = document.getElementById("uploadProgress");
    const bar = document.getElementById("uploadProgressBar");
    progress?.classList.add("active");
    if (bar) bar.style.width = "30%";

    const formData = new FormData();
    formData.append("file", file);

    try {
        if (bar) bar.style.width = "60%";
        const response = await axios.post(`${SERVER}${API_PATH.PCAP_UPLOAD_PATH}`, formData, {
            headers: { "Content-Type": "multipart/form-data" },
            timeout: 300000,
        });
        if (bar) bar.style.width = "100%";

        const data = response.data;
        let msg = data.message || "Upload successful";
        if (data.alerts?.length) {
            msg += ` (${data.alerts.length} alert(s) triggered)`;
        }
        showToast(TOAST_STATUS.SUCCESS, msg);

        if (typeof window.refreshFileList === "function") {
            window.refreshFileList();
        }
    } catch (err) {
        const detail = err.response?.data?.detail || err.message || "Upload failed";
        showToast(TOAST_STATUS.ERROR, typeof detail === "string" ? detail : JSON.stringify(detail));
    } finally {
        setTimeout(() => {
            progress?.classList.remove("active");
            if (bar) bar.style.width = "0%";
        }, 800);
    }
}

function renderCompareResult(data, el) {
    const fmt = (bytes) => {
        if (!bytes) return "0 B";
        const units = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
    };

    const pctRows = Object.entries(data.protocol_pct_diff || {})
        .sort((a, b) => b[1].diff - a[1].diff)
        .slice(0, 8)
        .map(([proto, v]) =>
            `<div class="compare-stat"><span>${proto.toUpperCase()}</span><span>A:${v.a}% B:${v.b}% (Δ${v.diff}%)</span></div>`
        ).join("");

    el.innerHTML = `
        <div class="compare-similarity">
            Protocol similarity: <strong>${data.similarity_pct}%</strong>
            ${data.same_content_likely ? '<br><small>Likely identical content</small>' : ""}
        </div>
        <div class="compare-summary">
            <div class="compare-file-card">
                <h4>${data.file_a.filename}</h4>
                <div class="compare-stat"><span>Size</span><span>${fmt(data.file_a.size_bytes)}</span></div>
                <div class="compare-stat"><span>Packets</span><span>${data.file_a.total_packets}</span></div>
                <div class="compare-stat"><span>Protocols</span><span>${data.file_a.protocols.length}</span></div>
                <div class="compare-stat"><span>Alerts</span><span>${data.file_a.alerts?.length || 0}</span></div>
            </div>
            <div class="compare-file-card">
                <h4>${data.file_b.filename}</h4>
                <div class="compare-stat"><span>Size</span><span>${fmt(data.file_b.size_bytes)}</span></div>
                <div class="compare-stat"><span>Packets</span><span>${data.file_b.total_packets}</span></div>
                <div class="compare-stat"><span>Protocols</span><span>${data.file_b.protocols.length}</span></div>
                <div class="compare-stat"><span>Alerts</span><span>${data.file_b.alerts?.length || 0}</span></div>
            </div>
        </div>
        <div class="compare-section">
            <h4>Common protocols (${data.common_protocols.length})</h4>
            ${data.common_protocols.map(p => `<span class="proto-tag common">${p}</span>`).join("") || "<em>None</em>"}
        </div>
        <div class="compare-section">
            <h4>Only in ${data.file_a.filename} (${data.only_in_a.length})</h4>
            ${data.only_in_a.map(p => `<span class="proto-tag only-a">${p}</span>`).join("") || "<em>None</em>"}
        </div>
        <div class="compare-section">
            <h4>Only in ${data.file_b.filename} (${data.only_in_b.length})</h4>
            ${data.only_in_b.map(p => `<span class="proto-tag only-b">${p}</span>`).join("") || "<em>None</em>"}
        </div>
        ${pctRows ? `<div class="compare-section"><h4>Protocol % difference (top)</h4>${pctRows}</div>` : ""}
        <div class="compare-section">
            <div class="compare-stat"><span>Size difference</span><span>${fmt(data.size_diff_bytes)}</span></div>
            <div class="compare-stat"><span>Packet difference</span><span>${data.packet_diff}</span></div>
        </div>
    `;
}

// --- ALERTS ---

function initAlerts() {
    document.getElementById("alertsBtn")?.addEventListener("click", openAlertsModal);
    document.getElementById("closeAlertsModal")?.addEventListener("click", closeAlertsModal);
    document.getElementById("addRuleBtn")?.addEventListener("click", addRule);
    document.getElementById("evalAllAlertsBtn")?.addEventListener("click", evaluateAllAlerts);
}

async function openAlertsModal() {
    document.getElementById("alertsModal")?.classList.remove("hidden");
    await loadAlertRules();
}

function closeAlertsModal() {
    document.getElementById("alertsModal")?.classList.add("hidden");
}

async function loadAlertRules() {
    try {
        const response = await axios.get(`${SERVER}${API_PATH.ALERT_RULES_PATH}`);
        alertRules = response.data.rules || [];
        renderRulesTable();
    } catch (err) {
        showToast(TOAST_STATUS.ERROR, "Failed to load alert rules");
    }
}

function renderRulesTable() {
    const tbody = document.getElementById("rulesTableBody");
    if (!tbody) return;

    if (!alertRules.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center">No rules configured</td></tr>';
        return;
    }

    tbody.innerHTML = alertRules.map(rule => `
        <tr>
            <td>${rule.name}</td>
            <td>${rule.type}</td>
            <td>${rule.severity || "medium"}</td>
            <td>
                <span class="rule-toggle ${rule.enabled !== false ? "rule-enabled" : "rule-disabled"}"
                      data-id="${rule.id}" title="Toggle enabled">
                    ${rule.enabled !== false ? "●" : "○"}
                </span>
            </td>
            <td>
                <button class="feature-btn danger" data-delete="${rule.id}" style="padding:4px 8px;font-size:11px">Delete</button>
            </td>
        </tr>
    `).join("");

    tbody.querySelectorAll(".rule-toggle").forEach(el => {
        el.addEventListener("click", () => toggleRule(el.dataset.id));
    });
    tbody.querySelectorAll("[data-delete]").forEach(el => {
        el.addEventListener("click", () => deleteRule(el.dataset.delete));
    });
}

async function toggleRule(ruleId) {
    const rule = alertRules.find(r => r.id === ruleId);
    if (!rule) return;
    try {
        await axios.put(`${SERVER}${API_PATH.ALERT_RULES_PATH}/${ruleId}`, {
            enabled: rule.enabled === false,
        });
        await loadAlertRules();
    } catch {
        showToast(TOAST_STATUS.ERROR, "Failed to toggle rule");
    }
}

async function deleteRule(ruleId) {
    try {
        await axios.delete(`${SERVER}${API_PATH.ALERT_RULES_PATH}/${ruleId}`);
        showToast(TOAST_STATUS.SUCCESS, "Rule deleted");
        await loadAlertRules();
    } catch {
        showToast(TOAST_STATUS.ERROR, "Failed to delete rule");
    }
}

async function addRule() {
    const name = document.getElementById("ruleName")?.value?.trim();
    const type = document.getElementById("ruleType")?.value;
    const severity = document.getElementById("ruleSeverity")?.value || "medium";
    const protocol = document.getElementById("ruleProtocol")?.value?.trim();
    const keyword = document.getElementById("ruleKeyword")?.value?.trim();
    const threshold = parseFloat(document.getElementById("ruleThreshold")?.value);

    if (!name || !type) {
        showToast(TOAST_STATUS.WARNING, "Name and type are required");
        return;
    }

    const body = { name, type, severity, enabled: true };
    if (protocol) body.protocol = protocol;
    if (keyword) body.keyword = keyword;
    if (!isNaN(threshold)) body.threshold = threshold;

    try {
        await axios.post(`${SERVER}${API_PATH.ALERT_RULES_PATH}`, body);
        showToast(TOAST_STATUS.SUCCESS, "Rule added");
        document.getElementById("ruleName").value = "";
        document.getElementById("ruleProtocol").value = "";
        document.getElementById("ruleKeyword").value = "";
        document.getElementById("ruleThreshold").value = "";
        await loadAlertRules();
    } catch (err) {
        showToast(TOAST_STATUS.ERROR, err.response?.data?.detail || "Failed to add rule");
    }
}

async function evaluateAllAlerts() {
    try {
        const response = await axios.post(`${SERVER}${API_PATH.ALERT_EVALUATE_ALL_PATH}`);
        const d = response.data;
        showToast(TOAST_STATUS.SUCCESS, `Evaluated ${d.evaluated} files, ${d.files_with_alerts} with alerts`);
        if (typeof window.refreshFileList === "function") {
            window.refreshFileList();
        }
    } catch {
        showToast(TOAST_STATUS.ERROR, "Failed to evaluate alerts");
    }
}

export function renderAlertBadge(file) {
    let alerts = file.alerts;
    if (typeof alerts === "string") {
        try { alerts = JSON.parse(alerts); } catch { alerts = []; }
    }
    if (!alerts?.length) return "";

    const top = alerts.reduce((best, a) => {
        const order = { high: 3, medium: 2, low: 1 };
        return (order[a.severity] || 0) > (order[best.severity] || 0) ? a : best;
    }, alerts[0]);

    const titles = alerts.map(a => `${a.name}: ${a.message}`).join("\n");
    return `<span class="alert-badge ${top.severity}" title="${titles.replace(/"/g, "&quot;")}">⚠ ${alerts.length}</span>`;
}

export function showFileAlerts(file) {
    let alerts = file.alerts;
    if (typeof alerts === "string") {
        try { alerts = JSON.parse(alerts); } catch { alerts = []; }
    }
    if (!alerts?.length) {
        showToast(TOAST_STATUS.INFO, "No alerts for this file");
        return;
    }
    const list = alerts.map(a =>
        `<div class="alert-list-item ${a.severity}"><strong>${a.name}</strong><br>${a.message}</div>`
    ).join("");
    const el = document.getElementById("compareResult");
    if (el) {
        document.getElementById("compareModal")?.classList.remove("hidden");
        el.innerHTML = `<h3 style="margin:0 0 12px">Alerts: ${file.filename}</h3>${list}`;
    }
}

// --- INIT ---

document.addEventListener("DOMContentLoaded", () => {
    initUpload();
    initAlerts();
});
