#!/usr/bin/env python3
"""Build stacked Tyler feature branches for pull requests."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "Tyler",
    "GIT_COMMITTER_NAME": "Tyler",
    "GIT_AUTHOR_EMAIL": "tyler@pcaptain.local",
    "GIT_COMMITTER_EMAIL": "tyler@pcaptain.local",
}


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    print("+", " ".join(args))
    return subprocess.run(
        args, cwd=ROOT, check=check, text=True, capture_output=True, env=GIT_ENV
    )


def write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    print(f"  wrote {path.relative_to(ROOT)}")


def strip_to_baseline() -> None:
    pcaps = (ROOT / "backend/routes/pcaps.py").read_text(encoding="utf-8")
    pcaps = re.sub(
        r"# Tyler code\nfrom fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, UploadFile, File\n",
        "from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query\n",
        pcaps,
        count=1,
    )
    pcaps = pcaps.replace(
        "from services.config import get_pcap_root_directories, get_upload_directory\n",
        "from services.config import get_pcap_root_directories\n",
    )
    pcaps = pcaps.replace(
        "from services.scan import PCAP_FILE_KEY_PREFIX, calculate_sha256, get_scan_service\n",
        "from services.scan import PCAP_FILE_KEY_PREFIX\n",
    )
    pcaps = re.sub(
        r"\nMAX_UPLOAD_BYTES = .*?\n\n",
        "\n",
        pcaps,
        count=1,
        flags=re.S,
    )
    pcaps = re.sub(
        r"\n@router\.post\(\"/pcaps/upload\".*?\n\n@router\.get\(\n    \"/pcaps/download",
        '\n@router.get(\n    "/pcaps/download',
        pcaps,
        count=1,
        flags=re.S,
    )
    pcaps = re.sub(
        r"\n@router\.get\(\"/pcaps/compare\".*?\n\n@router\.get\(\n    \"/pcaps/download",
        '\n@router.get(\n    "/pcaps/download',
        pcaps,
        count=1,
        flags=re.S,
    )
    pcaps = re.sub(r"\n\ndef _file_summary\(.*?\n    \}\n\n", "\n", pcaps, count=1, flags=re.S)
    write(ROOT / "backend/routes/pcaps.py", pcaps)

    main_py = (ROOT / "backend/main.py").read_text(encoding="utf-8")
    main_py = main_py.replace("from routes.analysis import router as analysis_router\n", "")
    main_py = main_py.replace("app.include_router(analysis_router)\n", "")
    write(ROOT / "backend/main.py", main_py)

    const_js = (ROOT / "frontend/components/constant.js").read_text(encoding="utf-8")
    const_js = const_js.replace('    PCAP_UPLOAD_PATH: "pcaps/upload",\n', "")
    const_js = const_js.replace('    PCAP_COMPARE_PATH: "pcaps/compare",\n', "")
    write(ROOT / "frontend/components/constant.js", const_js)

    html = (ROOT / "frontend/components/search-index.html").read_text(encoding="utf-8")
    html = html.replace(
        """        <div class="search-toolbar">
            <div class="search-row">
                <div class="search-input-wrap">
                    <input id="searchInput" type="text" placeholder="Search filename or protocol (e.g. eth !sip)" required autocomplete="off" />
                    <div id="suggestionBox" class="suggestion-box hidden"></div>
                </div>
                <button id="searchBtn">Search</button>
                <div id="spinnerSearchBtn" class="spinner-search-hidden"></div>
            </div>
            <div class="action-row">
                <button id="scanBtn">Scan</button>
                <div id="spinnerScanBtn" class="spinner-scan-hidden"></div>
                <button id="cancelScanBtn" class="danger-btn">Cancel Scan</button>
                <button id="dashboardBtn" onclick="location.href='/dashboard'" class="dashboard-btn" title="Go to Dashboard">
                    <i class="fa fa-bar-chart"></i>
                </button>
                <button id="configBtn" class="config-btn" title="Mount directory configuration">
                    <i class="fa fa-cog"></i>
                </button>
                <button id="uploadBtn" class="feature-btn" title="Upload PCAP">Upload</button>
                <button id="compareBtn" class="feature-btn" disabled title="Select 2 files to compare">
                    Compare <span id="compareCount" class="compare-selected-count"></span>
                </button>
                <button id="alertsBtn" class="feature-btn" title="Alert Rules">Alerts</button>
                <button id="clustersBtn" class="feature-btn" title="Cluster similar files">Clusters</button>
                <div class="scan-config-tooltip" id="scanConfigTooltip">
                    <i class="fa fa-info-circle" aria-hidden="true"></i>
                    <div class="scan-config-tooltip-content" id="scanConfigTooltipContent">
                        Loading scan config...
                    </div>
                </div>
            </div>
        </div>""",
        """        <div class="search-toolbar legacy-toolbar">
                <div class="search-input-wrap">
                    <input id="searchInput" type="text" placeholder="Search filename or protocol (e.g. eth !sip)" required autocomplete="off" />
                    <div id="suggestionBox" class="suggestion-box hidden"></div>
                </div>
                <button id="searchBtn">Search</button>
                <div id="spinnerSearchBtn" class="spinner-search-hidden"></div>
                <button id="scanBtn">Scan</button>
                <div id="spinnerScanBtn" class="spinner-scan-hidden"></div>
                <button id="cancelScanBtn" class="danger-btn">Cancel Scan</button>
                <button id="dashboardBtn" onclick="location.href='/dashboard'" class="dashboard-btn" title="Go to Dashboard">
                    <i class="fa fa-bar-chart"></i>
                </button>
                <button id="configBtn" class="config-btn" title="Mount directory configuration">
                    <i class="fa fa-cog"></i>
                </button>
                <button id="alertsBtn" class="feature-btn" title="Alert Rules">Alerts</button>
                <button id="clustersBtn" class="feature-btn" title="Cluster similar files">Clusters</button>
                <div class="scan-config-tooltip" id="scanConfigTooltip">
                    <i class="fa fa-info-circle" aria-hidden="true"></i>
                    <div class="scan-config-tooltip-content" id="scanConfigTooltipContent">
                        Loading scan config...
                    </div>
                </div>
        </div>""",
    )
    html = re.sub(
        r"\n        <div class=\"upload-zone\".*?</div>\n\n        <div class=\"table-container\">",
        "\n        <div class=\"table-container\">",
        html,
        count=1,
        flags=re.S,
    )
    html = html.replace(
        '                        <th class="compare-col"><i class="fa fa-check-square-o" title="Select to compare"></i></th>\n',
        "",
    )
    html = re.sub(
        r"\n        <!-- Compare Modal -->.*?\n        <!-- Alerts Modal -->",
        "\n        <!-- Alerts Modal -->",
        html,
        count=1,
        flags=re.S,
    )
    html = re.sub(
        r"\n        <!-- Analysis Modal \(IOC \+ Timeline\) -->.*?\n        <!-- Similar Files Modal -->",
        "\n        <!-- Similar Files Modal -->",
        html,
        count=1,
        flags=re.S,
    )
    html = html.replace('    <script type="module" src="analysis-script.js"></script>\n', "")
    write(ROOT / "frontend/components/search-index.html", html)

    features = (ROOT / "frontend/components/features-script.js").read_text(encoding="utf-8")
    features = re.sub(
        r"// Tyler code\nimport \{ showToast \} from \"./toast-script.js\";\nimport \{ API_PATH, SERVER, TOAST_STATUS \} from \"./constant.js\";\n\nconst compareSelection = new Set\(\);\nlet alertRules = \[\];\n\n// --- UPLOAD ---.*?// --- COMPARE ---\n\nfunction initCompare\(\) \{.*?\n\}\n\n",
        "// Tyler code\nimport { showToast } from \"./toast-script.js\";\nimport { API_PATH, SERVER, TOAST_STATUS } from \"./constant.js\";\n\nlet alertRules = [];\n\n",
        features,
        count=1,
        flags=re.S,
    )
    for pattern in (
        r"export function toggleCompareSelection\(.*?\n\}\n\n",
        r"function updateCompareUI\(\) \{.*?\n\}\n\n",
        r"function openCompareModal\(\) \{.*?\n\}\n\n",
        r"function closeCompareModal\(\) \{.*?\n\}\n\n",
        r"async function runCompare\(\) \{.*?\n\}\n\n",
    ):
        features = re.sub(pattern, "", features, count=1, flags=re.S)
    features = features.replace("    initUpload();\n    initCompare();\n", "")
    write(ROOT / "frontend/components/features-script.js", features)

    search_js = (ROOT / "frontend/components/search-script.js").read_text(encoding="utf-8")
    search_js = search_js.replace(
        'import { toggleCompareSelection, renderAlertBadge, showFileAlerts } from "./features-script.js";\n',
        'import { renderAlertBadge, showFileAlerts } from "./features-script.js";\n',
    )
    search_js = search_js.replace(
        '            <td data-label="Compare" class="compare-col">\n'
        '                ${fileHash ? `<input type="checkbox" class="compare-checkbox" data-hash="${fileHash}" />` : ""}\n'
        "            </td>\n",
        "",
    )
    search_js = re.sub(
        r"\n        const checkbox = tr\.querySelector\(\"\.compare-checkbox\"\);[\s\S]*?return;\n        \}\n",
        "\n",
        search_js,
        count=1,
    )
    write(ROOT / "frontend/components/search-script.js", search_js)

    info_html = (ROOT / "frontend/components/info-modal.html").read_text(encoding="utf-8")
    info_html = info_html.replace(
        '                <button type="button" id="infoEndpointsBtn" class="feature-btn">IOC / Timeline</button>\n',
        "",
    )
    write(ROOT / "frontend/components/info-modal.html", info_html)

    info_js = (ROOT / "frontend/components/info-modal.js").read_text(encoding="utf-8")
    info_js = info_js.replace('import { openAnalysisModal } from "./analysis-script.js";\n', "")
    info_js = re.sub(
        r"\n    document\.getElementById\(\"infoEndpointsBtn\"\)\?\.addEventListener\(\"click\",[\s\S]*?\n    \}\);\n",
        "\n",
        info_js,
        count=1,
    )
    write(ROOT / "frontend/components/info-modal.js", info_js)

    for rel in (
        "backend/routes/analysis.py",
        "backend/services/analysis.py",
        "frontend/components/analysis-script.js",
    ):
        path = ROOT / rel
        if path.exists():
            path.unlink()


def restore_paths(paths: list[str], tag: str = "tyler/snapshot-full") -> None:
    for rel in paths:
        result = run("git", "show", f"{tag}:{rel}", check=False)
        if result.returncode != 0:
            continue
        dest = ROOT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        write(dest, result.stdout)


def main() -> int:
    if not (ROOT / ".git").exists():
        run("git", "init")
        run("git", "checkout", "-b", "main")

    run("git", "add", "-A")
    status = run("git", "status", "--porcelain")
    if status.stdout.strip():
        run(
            "git",
            "commit",
            "-m",
            "chore: snapshot full tree before Tyler feature split",
        )
    run("git", "tag", "-f", "tyler/snapshot-full")

    strip_to_baseline()
    run("git", "add", "-A")
    run(
        "git",
        "commit",
        "-m",
        "chore: initial PCAP catalog core (scan, search, download)",
    )

    run("git", "branch", "-f", "tyler/web-pcap-upload")
    restore_paths(
        [
            "backend/routes/pcaps.py",
            "frontend/components/constant.js",
            "frontend/components/features-script.js",
            "frontend/components/search-index.html",
        ]
    )
    run("git", "add", "-A")
    run(
        "git",
        "commit",
        "-m",
        "feat: web PCAP upload with auto-scan after upload (Tyler code)",
    )

    run("git", "branch", "-f", "tyler/pcap-compare")
    restore_paths(
        [
            "backend/routes/pcaps.py",
            "frontend/components/constant.js",
            "frontend/components/features-script.js",
            "frontend/components/search-index.html",
            "frontend/components/search-script.js",
        ]
    )
    run("git", "add", "-A")
    run("git", "commit", "-m", "feat: compare two indexed PCAP files (Tyler code)")

    run("git", "branch", "-f", "tyler/ioc-extraction")
    restore_paths(
        [
            "backend/main.py",
            "backend/routes/analysis.py",
            "backend/services/analysis.py",
            "frontend/components/analysis-script.js",
            "frontend/components/info-modal.html",
            "frontend/components/info-modal.js",
            "frontend/components/search-index.html",
        ]
    )
    run("git", "add", "-A")
    run("git", "commit", "-m", "feat: IOC extraction per indexed PCAP file (Tyler code)")

    run("git", "branch", "-f", "tyler/search-toolbar-layout")
    restore_paths(
        [
            "frontend/components/search-index.html",
            "frontend/components/search-style.css",
        ]
    )
    run("git", "add", "-A")
    run(
        "git",
        "commit",
        "-m",
        "fix: split search toolbar into search and action rows (Tyler code)",
    )

    run("git", "branch", "-f", "tyler/develop")
    run("git", "checkout", "tyler/snapshot-full", "--", ".")
    run("git", "add", "-A")
    status = run("git", "status", "--porcelain")
    if status.stdout.strip():
        run("git", "commit", "-m", "chore: integrate remaining improvements on develop")

    run("git", "checkout", "tyler/develop")
    for branch in (
        "main",
        "tyler/web-pcap-upload",
        "tyler/pcap-compare",
        "tyler/ioc-extraction",
        "tyler/search-toolbar-layout",
        "tyler/develop",
    ):
        out = run("git", "rev-parse", "--short", branch)
        print(f"  {branch}: {out.stdout.strip()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
