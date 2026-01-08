import { showToast } from "./toast-script.js";
import { API_PATH, SERVER, TOAST_STATUS } from "./constant.js";

// Load excluded protocols from backend
async function loadExcludedProtocols() {
    try {
        const response = await axios.get(`${SERVER}${API_PATH.EXCLUDED_PROTOCOLS_PATH}`);
        const protocols = response.data || [];
        excludedProtocolsInput.value = protocols.join(", ");
    } catch (error) {
        console.error("Failed to load excluded protocols:", error);
        showToast(TOAST_STATUS.ERROR, "Failed to load excluded protocols");
    }
}


document.addEventListener("dynamic-dom-ready", () => {
    const configBtn = document.getElementById("configBtn");
    const configModal = document.getElementById("configModal");
    const closeConfigModal = document.getElementById("closeConfigModal");
    const excludedProtocolsInput = document.getElementById("excludedProtocolsInput");
    const resetExcludedBtn = document.getElementById("resetExcludedBtn");
    const saveExcludedBtn = document.getElementById("saveExcludedBtn");

    if (!configModal) return;

    // Open config modal
    if (configBtn) {
        configBtn.addEventListener("click", () => {
            configModal.classList.remove("hidden");
            loadExcludedProtocols();
        });
    }

    // Close config modal
    if (closeConfigModal) {
        closeConfigModal.addEventListener("click", () => {
            configModal.classList.add("hidden");
        });
    }

    // Close modal when clicking outside
    configModal.addEventListener("click", (e) => {
        if (e.target === configModal) {
            configModal.classList.add("hidden");
        }
    });

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" || e.key === "Esc") {
            if (configModal && !configModal.classList.contains("hidden")) {
                configModal.classList.add("hidden");
            }
        }
    });

    // Tab switching
    const configTabs = document.querySelectorAll(".config-tab");
    configTabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const targetTab = tab.getAttribute("data-tab");

            configTabs.forEach(t => t.classList.remove("active"));
            document
                .querySelectorAll(".tab-content")
                .forEach(c => c.classList.remove("active"));

            tab.classList.add("active");
            document
                .getElementById(targetTab + "Tab")
                ?.classList.add("active");
        });
    });

    // Reset
    if (resetExcludedBtn) {
        resetExcludedBtn.addEventListener("click", async () => {
            await loadExcludedProtocols();
            showToast(TOAST_STATUS.INFO, "Excluded protocols reset from server");
        });
    }

    // Save
    if (saveExcludedBtn) {
        saveExcludedBtn.addEventListener("click", async () => {
            try {
                const inputValue = excludedProtocolsInput.value.trim();
                const protocols = inputValue
                    .split(/[,\s]+/)
                    .map(p => p.trim())
                    .filter(Boolean);

                await axios.post(
                    `${SERVER}${API_PATH.EXCLUDED_PROTOCOLS_PATH}`,
                    protocols
                );

                showToast(
                    TOAST_STATUS.SUCCESS,
                    "Excluded protocols saved successfully"
                );
            } catch (error) {
                console.error(error);
                showToast(
                    TOAST_STATUS.ERROR,
                    "Failed to save excluded protocols"
                );
            }
        });
    }
});
