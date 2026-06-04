import { showToast } from "./toast-script.js";
import { API_PATH, SERVER, TOAST_STATUS } from "./constant.js";

function setToolsStatus(message) {
    const el = document.getElementById("toolsStatusLine");
    if (el) el.textContent = message || "";
}

function openCatalogToolsModal() {
    document.getElementById("catalogToolsModal")?.classList.remove("hidden");
    loadWebhooksList();
}

function closeCatalogToolsModal() {
    document.getElementById("catalogToolsModal")?.classList.add("hidden");
}

async function loadWebhooksList() {
    const list = document.getElementById("webhooksList");
    if (!list) return;
    list.innerHTML = "<span>Loading…</span>";
    try {
        const res = await axios.get(SERVER + API_PATH.WEBHOOKS_PATH);
        const hooks = res.data?.webhooks || [];
        if (!hooks.length) {
            list.innerHTML = "<span class=\"tools-status\">No webhooks configured.</span>";
            return;
        }
        list.innerHTML = "";
        hooks.forEach((hook) => {
            const row = document.createElement("div");
            row.className = "webhook-item";
            const url = hook.url || "";
            row.innerHTML = `<span title="${url}">${url}</span>`;
            const del = document.createElement("button");
            del.type = "button";
            del.className = "danger-btn";
            del.textContent = "Remove";
            del.addEventListener("click", () => removeWebhook(url));
            row.appendChild(del);
            list.appendChild(row);
        });
    } catch (err) {
        list.innerHTML = "<span class=\"tools-status\">Failed to load webhooks.</span>";
    }
}

async function removeWebhook(url) {
    try {
        await axios.delete(SERVER + API_PATH.WEBHOOKS_PATH, { params: { url } });
        showToast(TOAST_STATUS.SUCCESS, "Webhook removed");
        loadWebhooksList();
    } catch (err) {
        showToast(TOAST_STATUS.ERROR, "Failed to remove webhook");
    }
}

async function checkHealthReady() {
    const out = document.getElementById("healthReadyOutput");
    if (!out) return;
    out.classList.remove("hidden");
    out.textContent = "Checking…";
    try {
        const res = await axios.get(SERVER + API_PATH.HEALTH_READY_PATH);
        out.textContent = JSON.stringify(res.data, null, 2);
        const ok = res.data?.status === "ready";
        showToast(ok ? TOAST_STATUS.SUCCESS : TOAST_STATUS.WARNING, ok ? "System ready" : "System degraded");
    } catch (err) {
        const detail = err.response?.data || err.message;
        out.textContent = typeof detail === "string" ? detail : JSON.stringify(detail, null, 2);
        showToast(TOAST_STATUS.ERROR, "Readiness check failed");
    }
}

async function runBackfill() {
    setToolsStatus("Backfill running…");
    try {
        const res = await axios.post(SERVER + API_PATH.BACKFILL_ENDPOINTS_PATH);
        const d = res.data || {};
        setToolsStatus(`Done: ${d.updated ?? 0} updated, ${d.skipped ?? 0} skipped (${d.total ?? 0} total).`);
        showToast(TOAST_STATUS.SUCCESS, "Endpoint backfill completed");
    } catch (err) {
        setToolsStatus("");
        showToast(TOAST_STATUS.ERROR, err.response?.data?.detail || "Backfill failed");
    }
}

async function exportIndex() {
    setToolsStatus("Exporting…");
    try {
        const res = await axios.get(SERVER + API_PATH.INDEX_EXPORT_PATH);
        const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `pcaptain-catalog-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        setToolsStatus(`Exported ${res.data?.file_count ?? 0} files.`);
        showToast(TOAST_STATUS.SUCCESS, "Catalog exported");
    } catch (err) {
        setToolsStatus("");
        showToast(TOAST_STATUS.ERROR, "Export failed");
    }
}

async function importIndexFile(file) {
    if (!file) return;
    setToolsStatus("Importing…");
    try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const files = parsed.files || parsed;
        if (!Array.isArray(files)) {
            throw new Error("Invalid format: expected { files: [...] }");
        }
        const res = await axios.post(SERVER + API_PATH.INDEX_IMPORT_PATH, {
            files,
            merge: true
        });
        setToolsStatus(`Imported ${res.data?.imported ?? files.length} entries.`);
        showToast(TOAST_STATUS.SUCCESS, "Catalog import completed");
    } catch (err) {
        setToolsStatus("");
        showToast(TOAST_STATUS.ERROR, err.message || "Import failed");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("catalogToolsBtn")?.addEventListener("click", openCatalogToolsModal);
    document.getElementById("closeCatalogToolsBtn")?.addEventListener("click", closeCatalogToolsModal);
    document.getElementById("healthReadyBtn")?.addEventListener("click", checkHealthReady);
    document.getElementById("backfillEndpointsBtn")?.addEventListener("click", runBackfill);
    document.getElementById("exportIndexBtn")?.addEventListener("click", exportIndex);
    document.getElementById("addWebhookBtn")?.addEventListener("click", async () => {
        const input = document.getElementById("webhookUrl");
        const url = input?.value?.trim();
        if (!url) {
            return showToast(TOAST_STATUS.WARNING, "Enter a webhook URL");
        }
        try {
            await axios.post(SERVER + API_PATH.WEBHOOKS_PATH, {
                url,
                events: ["scan.completed"]
            });
            if (input) input.value = "";
            showToast(TOAST_STATUS.SUCCESS, "Webhook registered");
            loadWebhooksList();
        } catch (err) {
            showToast(TOAST_STATUS.ERROR, "Failed to register webhook");
        }
    });
    document.getElementById("importIndexFile")?.addEventListener("change", (e) => {
        const file = e.target.files?.[0];
        importIndexFile(file);
        e.target.value = "";
    });
});

export { closeCatalogToolsModal, openCatalogToolsModal };
