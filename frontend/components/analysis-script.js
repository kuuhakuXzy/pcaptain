// Tyler code
import { showToast } from "./toast-script.js";
import { API_PATH, SERVER, TOAST_STATUS } from "./constant.js";

let analysisChart = null;
let currentAnalysisFile = null;

function getFileHash(file) {
    const url = file.download_url || "";
    const match = url.match(/\/pcaps\/download\/([a-f0-9]+)/i);
    return match ? match[1] : null;
}

export function updateInfoModalRisk(file) {
    const scoreEl = document.getElementById("infoRiskScore");
    const factorsEl = document.getElementById("infoRiskFactors");
    if (!scoreEl) return;

    let alerts = file.alerts;
    if (typeof alerts === "string") {
        try { alerts = JSON.parse(alerts); } catch { alerts = []; }
    }
    if (!alerts?.length) {
        scoreEl.textContent = "Low";
        if (factorsEl) factorsEl.innerHTML = "";
        return;
    }

    let score = 0;
    const factors = [];
    alerts.forEach(a => {
        if (a.severity === "high") score += 30;
        else if (a.severity === "medium") score += 15;
        else score += 5;
        factors.push(`<div class="risk-factor ${a.severity}">${a.name}</div>`);
    });
    score = Math.min(100, score);
    const level = score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";
    scoreEl.textContent = `${level} (${score})`;
    if (factorsEl) factorsEl.innerHTML = factors.join("");
}

function initAnalysis() {
    document.getElementById("clustersBtn")?.addEventListener("click", openClustersModal);
    document.getElementById("closeClustersModal")?.addEventListener("click", closeClustersModal);
    document.getElementById("refreshClustersBtn")?.addEventListener("click", () => loadClusters(true));

    document.getElementById("closeAnalysisModal")?.addEventListener("click", closeAnalysisModal);
    document.querySelectorAll(".analysis-tab").forEach(tab => {
        tab.addEventListener("click", () => switchAnalysisTab(tab.dataset.tab));
    });

    document.getElementById("infoEndpointsBtn")?.addEventListener("click", () => {
        if (currentAnalysisFile) openAnalysisModal(currentAnalysisFile, "ioc");
    });
    document.getElementById("infoSimilarBtn")?.addEventListener("click", () => {
        if (currentAnalysisFile) openSimilarFromInfo(currentAnalysisFile);
    });
}

export function setCurrentAnalysisFile(file) {
    currentAnalysisFile = file;
}

export async function openAnalysisModal(file, tab = "ioc") {
    const hash = getFileHash(file);
    if (!hash) {
        showToast(TOAST_STATUS.ERROR, "Cannot resolve file hash");
        return;
    }
    currentAnalysisFile = file;
    document.getElementById("analysisModal")?.classList.remove("hidden");
    document.getElementById("analysisTitle").textContent = `Analysis: ${file.filename}`;
    switchAnalysisTab(tab);
    if (tab === "ioc") await loadIoc(hash);
    if (tab === "timeline") await loadTimeline(hash);
}

function closeAnalysisModal() {
    document.getElementById("analysisModal")?.classList.add("hidden");
    if (analysisChart) {
        analysisChart.destroy();
        analysisChart = null;
    }
}

function switchAnalysisTab(tab) {
    document.querySelectorAll(".analysis-tab").forEach(t => {
        t.classList.toggle("active", t.dataset.tab === tab);
    });
    document.querySelectorAll(".analysis-panel").forEach(p => {
        p.classList.toggle("hidden", p.id !== `panel-${tab}`);
    });
    const hash = currentAnalysisFile ? getFileHash(currentAnalysisFile) : null;
    if (hash && tab === "ioc") loadIoc(hash);
    if (hash && tab === "timeline") loadTimeline(hash);
}

async function loadIoc(hash) {
    const el = document.getElementById("iocContent");
    if (!el) return;
    el.innerHTML = "<p>Extracting IOCs...</p>";
    try {
        const res = await axios.get(`${SERVER}pcaps/${hash}/ioc`);
        renderIoc(res.data, el);
    } catch (err) {
        el.innerHTML = `<p class="error-text">${err.response?.data?.detail || "Failed to load IOCs"}</p>`;
    }
}

function renderIoc(data, el) {
    const truncNote = data.truncated
        ? `<p class="analysis-note">Analyzed first ${data.packets_analyzed} packets (file truncated for performance)</p>`
        : `<p class="analysis-note">Analyzed ${data.packets_analyzed} packets</p>`;

    const ipRows = (data.ips || []).slice(0, 20).map(i => `
        <tr>
            <td>${i.ip}</td>
            <td>${i.count}</td>
            <td>${i.role}</td>
            <td>${i.is_private ? "private" : "public"}</td>
        </tr>`).join("") || "<tr><td colspan='4'>None</td></tr>";

    const portRows = (data.ports || []).slice(0, 15).map(p => `
        <tr><td>${p.port}</td><td>${p.protocol.toUpperCase()}</td><td>${p.count}</td></tr>`
    ).join("") || "<tr><td colspan='3'>None</td></tr>";

    const domainRows = (data.domains || []).slice(0, 15).map(d => `
        <tr><td>${d.domain}</td><td>${d.count}</td></tr>`
    ).join("") || "<tr><td colspan='2'>None</td></tr>";

    const flowRows = (data.flows || []).slice(0, 15).map(f => `
        <tr><td>${f.flow}</td><td>${f.protocol.toUpperCase()}</td><td>${f.count}</td></tr>`
    ).join("") || "<tr><td colspan='3'>None</td></tr>";

    el.innerHTML = `
        ${truncNote}
        <div class="analysis-section">
            <h4>IP Addresses (${data.ips?.length || 0})</h4>
            <table class="analysis-table"><thead><tr><th>IP</th><th>Count</th><th>Role</th><th>Type</th></tr></thead><tbody>${ipRows}</tbody></table>
        </div>
        <div class="analysis-section">
            <h4>Ports (${data.ports?.length || 0})</h4>
            <table class="analysis-table"><thead><tr><th>Port</th><th>Proto</th><th>Count</th></tr></thead><tbody>${portRows}</tbody></table>
        </div>
        <div class="analysis-section">
            <h4>Domains (${data.domains?.length || 0})</h4>
            <table class="analysis-table"><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody>${domainRows}</tbody></table>
        </div>
        <div class="analysis-section">
            <h4>Top Flows (${data.flows?.length || 0})</h4>
            <table class="analysis-table"><thead><tr><th>Flow</th><th>Proto</th><th>Count</th></tr></thead><tbody>${flowRows}</tbody></table>
        </div>`;
}

async function loadTimeline(hash) {
    const el = document.getElementById("timelineContent");
    if (!el) return;
    el.innerHTML = "<p>Building timeline...</p>";
    try {
        const res = await axios.get(`${SERVER}pcaps/${hash}/timeline`, { params: { bucket_seconds: 1 } });
        renderTimeline(res.data, el);
    } catch (err) {
        el.innerHTML = `<p class="error-text">${err.response?.data?.detail || "Failed to load timeline"}</p>`;
    }
}

function renderTimeline(data, el) {
    const buckets = data.buckets || [];
    if (!buckets.length) {
        el.innerHTML = "<p>No timeline data available</p>";
        return;
    }

    el.innerHTML = `
        <p class="analysis-note">Duration: ${data.total_duration}s · ${data.packets_analyzed} packets · bucket ${data.bucket_seconds}s
        ${data.truncated ? " · truncated" : ""}</p>
        <canvas id="timelineChart" height="120"></canvas>
        <div id="timelineProtoLegend" class="timeline-legend"></div>`;

    const labels = buckets.map(b => `${b.time_start}s`);
    const totals = buckets.map(b => b.packets);

    const protoSet = new Set();
    buckets.forEach(b => Object.keys(b.protocols || {}).forEach(p => protoSet.add(p)));
    const topProtos = [...protoSet].slice(0, 5);

    const colors = ["#0060A9", "#e74c3c", "#27ae60", "#f39c12", "#9b59b6"];
    const datasets = [
        {
            label: "Total packets",
            data: totals,
            borderColor: "#0060A9",
            backgroundColor: "rgba(0,96,169,0.15)",
            fill: true,
            tension: 0.3,
            yAxisID: "y",
        },
    ];

    topProtos.forEach((proto, i) => {
        datasets.push({
            label: proto.toUpperCase(),
            data: buckets.map(b => (b.protocols || {})[proto] || 0),
            borderColor: colors[(i + 1) % colors.length],
            tension: 0.3,
            fill: false,
            yAxisID: "y1",
        });
    });

    const canvas = document.getElementById("timelineChart");
    if (analysisChart) analysisChart.destroy();
    analysisChart = new Chart(canvas, {
        type: "line",
        data: { labels, datasets },
        options: {
            responsive: true,
            interaction: { mode: "index", intersect: false },
            plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
            scales: {
                x: { title: { display: true, text: "Time (seconds)" }, ticks: { maxTicksLimit: 15 } },
                y: { position: "left", title: { display: true, text: "Packets/bucket" }, beginAtZero: true },
                y1: { position: "right", beginAtZero: true, grid: { drawOnChartArea: false } },
            },
        },
    });
}

async function openSimilarFromInfo(file) {
    const hash = getFileHash(file);
    if (!hash) return;
    document.getElementById("similarModal")?.classList.remove("hidden");
    const el = document.getElementById("similarContent");
    el.innerHTML = "<p>Searching similar files...</p>";
    try {
        const res = await axios.get(`${SERVER}pcaps/${hash}/similar`, { params: { limit: 10, min_similarity: 40 } });
        const similar = res.data.similar || [];
        if (!similar.length) {
            el.innerHTML = "<p>No similar files found (threshold 40%)</p>";
            return;
        }
        el.innerHTML = `
            <p class="analysis-note">Files with similar protocol profile to <strong>${file.filename}</strong></p>
            <table class="analysis-table">
                <thead><tr><th>Filename</th><th>Similarity</th><th>Protocols</th></tr></thead>
                <tbody>${similar.map(s => `
                    <tr>
                        <td>${s.filename}</td>
                        <td><strong>${s.similarity_pct}%</strong></td>
                        <td>${(s.protocols || []).slice(0, 6).join(", ")}</td>
                    </tr>`).join("")}
                </tbody>
            </table>`;
    } catch (err) {
        el.innerHTML = `<p class="error-text">${err.response?.data?.detail || "Failed"}</p>`;
    }
}

function openClustersModal() {
    document.getElementById("clustersModal")?.classList.remove("hidden");
    loadClusters(false);
}

function closeClustersModal() {
    document.getElementById("clustersModal")?.classList.add("hidden");
}

async function loadClusters(refresh = false) {
    const el = document.getElementById("clustersContent");
    if (!el) return;
    el.innerHTML = "<p>Clustering files...</p>";
    const threshold = parseFloat(document.getElementById("clusterThreshold")?.value || 70);
    try {
        const res = await axios.get(`${SERVER}${API_PATH.PCAP_CLUSTERS_PATH}`, {
            params: { threshold, refresh },
        });
        renderClusters(res.data, el);
    } catch (err) {
        el.innerHTML = `<p class="error-text">${err.response?.data?.detail || "Failed to load clusters"}</p>`;
    }
}

function renderClusters(data, el) {
    const clusters = data.clusters || [];
    if (!clusters.length) {
        el.innerHTML = "<p>No clusters found. Try lowering the threshold.</p>";
        return;
    }

    el.innerHTML = `
        <p class="analysis-note">${data.total_files} files → ${data.cluster_count} clusters (threshold ${data.threshold}%)</p>
        ${clusters.map(c => `
            <div class="cluster-card">
                <div class="cluster-header">
                    <strong>${c.label}</strong>
                    <span class="cluster-meta">${c.file_count} files · avg similarity ${c.avg_internal_similarity || "—"}%</span>
                </div>
                <ul class="cluster-file-list">
                    ${c.files.map(f => `<li>${f.filename}</li>`).join("")}
                </ul>
            </div>`).join("")}`;
}

document.addEventListener("DOMContentLoaded", initAnalysis);
