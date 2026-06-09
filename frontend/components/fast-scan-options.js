/** Shared fast-scan UI helpers (Search + Ops). */

export const FAST_SCAN_STORAGE_KEY = "pcaptain.fast_scan_options";

export const SEARCH_FAST_IDS = {
    panel: "fastScanOptionsPanel",
    notActive: "fastScanNotActiveNotice",
    summary: "fastScanSummary",
    output: "fastOutputSelect",
    sampleEnable: "fastSampleEnable",
    sampleEvery: "fastSampleEvery",
    maxPacketsEnable: "fastMaxPacketsEnable",
    maxPackets: "fastMaxPackets",
    bpf: "fastBpfFilter",
    fingerprintEnable: "fastFingerprintEnable",
    portsFile: "fastPortsFile",
};

export const OPS_FAST_IDS = {
    panel: "opsFastScanPanel",
    notActive: "opsFastScanNotActiveNotice",
    summary: "opsFastScanSummary",
    output: "opsFastOutputSelect",
    sampleEnable: "opsFastSampleEnable",
    sampleEvery: "opsFastSampleEvery",
    maxPacketsEnable: "opsFastMaxPacketsEnable",
    maxPackets: "opsFastMaxPackets",
    bpf: "opsFastBpfFilter",
    fingerprintEnable: "opsFastFingerprintEnable",
    portsFile: "opsFastPortsFile",
};

function el(id) {
    return document.getElementById(id);
}

export function isFastScanMode(config) {
    return (config?.scan_mode || "").toLowerCase() === "fast";
}

export function wireFastScanOptionToggles(ids) {
    const sampleEn = el(ids.sampleEnable);
    const sampleN = el(ids.sampleEvery);
    const maxEn = el(ids.maxPacketsEnable);
    const maxN = el(ids.maxPackets);
    if (sampleEn && sampleN && !sampleEn.dataset.wired) {
        sampleEn.dataset.wired = "1";
        sampleEn.addEventListener("change", () => {
            sampleN.disabled = !sampleEn.checked;
            updateFastScanSummary(ids, cachedConfigForSummary(ids));
        });
    }
    if (maxEn && maxN && !maxEn.dataset.wired) {
        maxEn.dataset.wired = "1";
        maxEn.addEventListener("change", () => {
            maxN.disabled = !maxEn.checked;
            updateFastScanSummary(ids, cachedConfigForSummary(ids));
        });
    }
    const fields = [ids.output, ids.bpf, ids.fingerprintEnable, ids.portsFile, ids.sampleEvery, ids.maxPackets];
    for (const fid of fields) {
        const node = el(fid);
        if (node && !node.dataset.fastSummaryWired) {
            node.dataset.fastSummaryWired = "1";
            node.addEventListener("change", () => updateFastScanSummary(ids, cachedConfigForSummary(ids)));
            node.addEventListener("input", () => updateFastScanSummary(ids, cachedConfigForSummary(ids)));
        }
    }
}

const summaryConfigByPanel = new Map();

export function setFastScanPanelConfig(ids, config) {
    summaryConfigByPanel.set(ids.panel, config);
}

function cachedConfigForSummary(ids) {
    return summaryConfigByPanel.get(ids.panel) || null;
}

export function applyFastScanDefaultsToForm(ids, defs = {}) {
    const outSel = el(ids.output);
    if (outSel && defs.output) outSel.value = defs.output;
    const fp = el(ids.fingerprintEnable);
    if (fp) fp.checked = !!defs.emit_fingerprint;
    const ports = el(ids.portsFile);
    if (ports) ports.value = defs.ports_file || "";
    const sampleEn = el(ids.sampleEnable);
    const sampleN = el(ids.sampleEvery);
    if (sampleEn && sampleN) {
        if (defs.sample_every) {
            sampleEn.checked = true;
            sampleN.disabled = false;
            sampleN.value = defs.sample_every;
        } else {
            sampleEn.checked = false;
            sampleN.disabled = true;
        }
    }
    const maxEn = el(ids.maxPacketsEnable);
    const maxN = el(ids.maxPackets);
    if (maxEn && maxN) {
        if (defs.max_packets) {
            maxEn.checked = true;
            maxN.disabled = false;
            maxN.value = defs.max_packets;
        } else {
            maxEn.checked = false;
            maxN.disabled = true;
        }
    }
    const bpf = el(ids.bpf);
    if (bpf) bpf.value = defs.bpf_filter || "";
}

export function loadFastScanPrefs() {
    try {
        const raw = localStorage.getItem(FAST_SCAN_STORAGE_KEY);
        return raw ? JSON.parse(raw) : null;
    } catch (_) {
        return null;
    }
}

export function saveFastScanPrefs(opts) {
    if (!opts) return;
    try {
        localStorage.setItem(FAST_SCAN_STORAGE_KEY, JSON.stringify(opts));
    } catch (_) {
        /* ignore quota */
    }
}

export function collectFastScanOptions(ids, config) {
    if (!isFastScanMode(config)) {
        return null;
    }
    const opts = {
        output: el(ids.output)?.value || "summary",
    };
    if (el(ids.sampleEnable)?.checked) {
        const n = parseInt(el(ids.sampleEvery)?.value, 10);
        if (n >= 2) opts.sample_every = n;
    }
    if (el(ids.maxPacketsEnable)?.checked) {
        const m = parseInt(el(ids.maxPackets)?.value, 10);
        if (m >= 1) opts.max_packets = m;
    }
    const bpf = el(ids.bpf)?.value?.trim();
    if (bpf) opts.bpf_filter = bpf;
    if (el(ids.fingerprintEnable)?.checked) {
        opts.emit_fingerprint = true;
    }
    const ports = el(ids.portsFile)?.value?.trim();
    if (ports) opts.ports_file = ports;
    return opts;
}

export function formatFastScanOptionsSummary(opts) {
    if (!opts) return "Fast scan options not applied (server not in fast mode).";
    const parts = [];
    parts.push(opts.output === "lines" ? "per-packet lines" : "summary");
    if (opts.sample_every) parts.push(`sample 1/${opts.sample_every}`);
    if (opts.max_packets) parts.push(`max ${opts.max_packets} packets`);
    if (opts.bpf_filter) parts.push(`BPF: ${opts.bpf_filter}`);
    if (opts.emit_fingerprint) parts.push("fingerprint on");
    if (opts.ports_file) parts.push(`ports file: ${opts.ports_file}`);
    return `This scan: ${parts.join(" · ")}`;
}

export function updateFastScanSummary(ids, config) {
    const summaryEl = el(ids.summary);
    if (!summaryEl) return;
    if (!isFastScanMode(config)) {
        summaryEl.textContent = "";
        summaryEl.classList.add("hidden");
        return;
    }
    const opts = collectFastScanOptions(ids, config);
    summaryEl.textContent = formatFastScanOptionsSummary(opts);
    summaryEl.classList.remove("hidden");
}

export function updateFastScanOptionsPanel(ids, config) {
    setFastScanPanelConfig(ids, config);
    const panel = el(ids.panel);
    const notice = el(ids.notActive);
    const isFast = isFastScanMode(config);
    if (panel) panel.classList.toggle("hidden", !isFast);
    if (notice) notice.classList.toggle("hidden", isFast);
    if (!isFast) {
        updateFastScanSummary(ids, config);
        return;
    }
    const defs = { ...(config?.fast_scan_defaults || {}) };
    const saved = loadFastScanPrefs();
    if (saved) {
        Object.assign(defs, saved);
    }
    applyFastScanDefaultsToForm(ids, defs);
    updateFastScanSummary(ids, config);
}

export function applyFastScanPreset(ids, config, preset) {
    if (!isFastScanMode(config)) return;
    const defs = config?.fast_scan_defaults || {};
    if (preset === "default") {
        applyFastScanDefaultsToForm(ids, defs);
    } else if (preset === "large") {
        applyFastScanDefaultsToForm(ids, {
            ...defs,
            output: "summary",
            sample_every: 10,
            max_packets: 500000,
            bpf_filter: "",
            emit_fingerprint: false,
        });
    } else if (preset === "dup") {
        applyFastScanDefaultsToForm(ids, {
            ...defs,
            output: "summary",
            emit_fingerprint: true,
            bpf_filter: "",
        });
        const sampleEn = el(ids.sampleEnable);
        const sampleN = el(ids.sampleEvery);
        const maxEn = el(ids.maxPacketsEnable);
        const maxN = el(ids.maxPackets);
        if (sampleEn && sampleN) {
            sampleEn.checked = false;
            sampleN.disabled = true;
        }
        if (maxEn && maxN) {
            maxEn.checked = false;
            maxN.disabled = true;
        }
    }
    updateFastScanSummary(ids, config);
}

export function updateScanModeBadge(badgeId, config) {
    const badge = el(badgeId);
    if (!badge) return;
    const mode = (config?.scan_mode || "full").toLowerCase();
    badge.textContent = mode.toUpperCase();
    badge.className = `scan-mode-badge scan-mode-${mode}`;
    badge.classList.remove("hidden");
    badge.title =
        mode === "fast"
            ? "Fast mode — per-scan options below apply to every PCAP in this job"
            : `Server scan mode: ${mode}. Set pcap.scan_mode: fast in config to enable fast options.`;
}
