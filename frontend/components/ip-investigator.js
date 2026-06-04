/**
 * IP investigator — find PCAPs containing an IP (and optional port), then copy paths / CSV / Wireshark helpers.
 */
import { showToast } from "./toast-script.js";
import { TOAST_STATUS } from "./constant.js";

function getApi() {
    return window.pcaptainSearch;
}

function setSummary(html, visible = true) {
    const el = document.getElementById("investigatorSummary");
    const actions = document.getElementById("investigatorActions");
    if (!el) return;
    el.innerHTML = html;
    el.classList.toggle("hidden", !visible);
    if (actions) actions.classList.toggle("hidden", !visible);
}

function setLoading(on) {
    const btn = document.getElementById("investigatorSearchBtn");
    if (btn) {
        btn.disabled = on;
        btn.textContent = on ? "Searching…" : "Find PCAPs";
    }
}

function validateIp(ip) {
    const v4 =
        /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
    const v6 = /^[0-9a-f:]+$/i;
    return v4.test(ip) || (ip.includes(":") && v6.test(ip));
}

async function runInvestigation() {
    const ipInput = document.getElementById("investigatorIp");
    const portInput = document.getElementById("investigatorPort");
    const ip = ipInput?.value?.trim() || "";
    const portRaw = portInput?.value?.trim() || "";

    if (!ip) {
        showToast(TOAST_STATUS.WARNING, "Enter an IP address to investigate");
        ipInput?.focus();
        return;
    }
    if (!validateIp(ip)) {
        showToast(TOAST_STATUS.WARNING, "Invalid IP (e.g. 192.168.1.10)");
        return;
    }

    let port = null;
    if (portRaw) {
        port = parseInt(portRaw, 10);
        if (port < 1 || port > 65535) {
            showToast(TOAST_STATUS.WARNING, "Port must be between 1 and 65535");
            return;
        }
    }

    const api = getApi();
    if (!api?.runIpInvestigation) {
        showToast(TOAST_STATUS.ERROR, "Page not ready — refresh the browser");
        return;
    }

    setLoading(true);
    setSummary('<span class="investigator-loading">Searching catalog…</span>', true);

    try {
        const result = await api.runIpInvestigation(ip, port);
        const total = result.total ?? 0;
        const portLabel = port ? ` and port <strong>${port}</strong>` : "";

        if (total === 0) {
            setSummary(
                `No PCAPs contain IP <strong>${ip}</strong>${portLabel}. ` +
                    `Run <em>Scan</em> or <em>Tools → Backfill IP/port</em> if you added files recently.`,
                true
            );
            document.getElementById("investigatorActions")?.classList.add("hidden");
            return;
        }

        const pageNote =
            total > result.shown
                ? ` (showing ${result.shown} of ${total} — use the table below to paginate)`
                : "";

        setSummary(
            `Found <strong>${total}</strong> PCAP file(s) with IP <strong>${ip}</strong>${portLabel}${pageNote}.`,
            true
        );
        document.getElementById("investigatorActions")?.classList.remove("hidden");

        document.getElementById("resultTable")?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
        const msg = err.message || "Investigation failed";
        setSummary(`<span class="investigator-error">${msg}</span>`, true);
        showToast(TOAST_STATUS.ERROR, msg);
    } finally {
        setLoading(false);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("investigatorSearchBtn")?.addEventListener("click", runInvestigation);
    document.getElementById("investigatorIp")?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") runInvestigation();
    });
    document.getElementById("investigatorPort")?.addEventListener("keypress", (e) => {
        if (e.key === "Enter") runInvestigation();
    });

    document.getElementById("investigatorCopyPaths")?.addEventListener("click", async () => {
        const api = getApi();
        if (!api?.copyAllMatchingPaths) return;
        await api.copyAllMatchingPaths();
    });

    document.getElementById("investigatorExportCsv")?.addEventListener("click", async () => {
        const api = getApi();
        if (!api?.exportMatchingCsv) return;
        await api.exportMatchingCsv();
    });

    document.getElementById("investigatorWiresharkHint")?.addEventListener("click", () => {
        const api = getApi();
        if (!api?.copyWiresharkCommand) return;
        api.copyWiresharkCommand();
    });

    document.getElementById("investigatorWiresharkBatch")?.addEventListener("click", async () => {
        const api = getApi();
        if (!api?.exportWiresharkBatch) return;
        await api.exportWiresharkBatch();
    });
});
