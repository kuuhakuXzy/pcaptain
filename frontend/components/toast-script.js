// toast-script.js
import { TOAST_STATUS } from "./constant.js";

export function showToast(status, message) {
    let toastBox = document.getElementById("toastBox");

    if (!toastBox) {
        toastBox = document.createElement("div");
        toastBox.id = "toastBox";
        toastBox.classList.add("toast-box");
        document.body.appendChild(toastBox);
    }

    const toast = document.createElement("div");
    toast.classList.add("toast");

    if (status === TOAST_STATUS.SUCCESS) {
        toast.innerHTML = `
            <i class="fa fa-check"></i> 
            <span>${message}</span>
            <span class="close-btn">&times;</span>
        `;
        toast.classList.add("success");
    } else if (status === TOAST_STATUS.WARNING) {
        toast.innerHTML = `
            <i class="fa fa-exclamation-triangle"></i>
            <span>${message}</span>
            <span class="close-btn">&times;</span>
        `;
        toast.classList.add("warning");
    } else if (status === TOAST_STATUS.NOT_FOUND) {
        toast.innerHTML = `
            <i class="fa fa-exclamation-circle"></i>
            <span>${message}</span>
            <span class="close-btn">&times;</span>
        `;
        toast.classList.add("not-found");
    } else if (status == TOAST_STATUS.ERROR) {
        toast.innerHTML = `
            <i class="fa fa-window-close"></i>
            <span>${message}</span>
            <span class="close-btn">&times;</span>
        `;
        toast.classList.add("error");
    }

    toastBox.appendChild(toast);

    // Automatically close after 4s
    let autoRemove = setTimeout(() => { closeToast(toast) }, 4000);

    // Close when clicking "X"
    toast.querySelector(".close-btn").addEventListener("click", () => {
        clearTimeout(autoRemove);
        closeToast(toast);
    })
}

function closeToast(toast) {
    toast.classList.add("hide");
    setTimeout(() => {
        toast.remove();
    }, 400);
}