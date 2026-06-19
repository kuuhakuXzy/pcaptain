import { SERVER, API_PATH } from "../constant.js";

const loadingIndicator = document.getElementById('loadingIndicator');
const errorMessage = document.getElementById('errorMessage');
const dashboardContent = document.getElementById('dashboardContent');
const refreshBtn = document.getElementById('refreshBtn');
const lastUpdatedEl = document.getElementById('lastUpdated');

let charts = {};
let pollInterval = null;
let captureYearTableData = [];

const CHART_COLORS = [
    'rgba(102, 126, 234, 0.8)',
    'rgba(118, 75, 162, 0.8)',
    'rgba(16, 185, 129, 0.8)',
    'rgba(245, 158, 11, 0.8)',
    'rgba(239, 68, 68, 0.8)',
    'rgba(59, 130, 246, 0.8)',
    'rgba(168, 85, 247, 0.8)',
    'rgba(236, 72, 153, 0.8)',
    'rgba(20, 184, 166, 0.8)',
    'rgba(251, 146, 60, 0.8)',
];

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    loadDashboardData();
    initCaptureYearModal();

    window.addEventListener('pcap-index-changed', () => {
        loadDashboardData(true);
    });

    refreshBtn.addEventListener('click', () => {
        loadDashboardData(true);
    });
});

async function loadDashboardData(forceRefresh = false) {
    showLoading();
    refreshBtn.disabled = true;

    try {
        const response = await axios.get(`${SERVER}${API_PATH.DASHBOARD_SUMMARY_PATH}`, {
            params: {
                refresh: forceRefresh
            }
        });
        
        if (response.status === 202) {
            // Still processing
            showLoading();
            if (!pollInterval) {
                pollInterval = setInterval(() => loadDashboardData(), 2000);
            }
            return;
        }

        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }

        if (response.data.status === 'idle' && response.data.data) {
            renderDashboard(response.data.data);
        } else {
            showError('Unexpected response format');
        }
    } catch (error) {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
        
        console.error('Error loading dashboard:', error);
        showError(error.response?.data?.detail || 'Failed to load dashboard data');
    } finally {
        refreshBtn.disabled = false;
    }
}

function showLoading() {
    loadingIndicator.classList.remove('hidden');
    errorMessage.classList.add('hidden');
    dashboardContent.classList.add('hidden');
}

function showError(message) {
    loadingIndicator.classList.add('hidden');
    dashboardContent.classList.add('hidden');
    errorMessage.classList.remove('hidden');
    errorMessage.textContent = message;
}

function showDashboard() {
    loadingIndicator.classList.add('hidden');
    errorMessage.classList.add('hidden');
    dashboardContent.classList.remove('hidden');
}

function renderDashboard(data) {
    console.log("combo data:", data.protocol_combination_distribution);
    showDashboard();
    
    // Update timestamp
    const date = new Date(data.generated_at * 1000);
    lastUpdatedEl.textContent = date.toLocaleString();

    // Update total files
    document.getElementById('totalFiles').textContent = data.total_files || 0;

    // Destroy existing charts
    Object.values(charts).forEach(chart => chart.destroy());
    charts = {};

    // Render file system tables
    renderDirectoryTable(data.directory_distribution || {});
    renderExtensionTable(data.extension_distribution || {});
    captureYearTableData = data.capture_year_table || [];
    renderCaptureYearSection(
        data.capture_year_distribution || {},
        captureYearTableData
    );

    // Render scan mode stats
    renderScanModeStats(data.scan_mode_distribution || {}, data.total_files || 0);

    // Render charts
    charts.sizeDistChart = createBarChart(
        'sizeDistChart',
        data.pcap_size_distribution,
        'Files',
        ['<10MB', '10-100MB', '100MB-1GB', '>1GB']
    );

    charts.packetDistChart = createBarChart(
        'packetDistChart',
        data.packet_count_distribution,
        'Files',
        ['0', '<1k', '1k-100k', '>100k']
    );

    charts.protocolPresenceChart = createHorizontalBarChart(
        'protocolPresenceChart',
        data.protocol_presence_distribution,
        'Files'
    );

    charts.diversityChart = createPieChart(
        'diversityChart',
        data.protocol_diversity_distribution,
        'Protocol Count',
        data.protocol_diversity_details || {}
    );

    const comboData = data.protocol_combination_distribution || {};
    console.log('combo data:', comboData);
    console.log('combo keys:', Object.keys(comboData));

    charts.protocolComboChart = createProtocolComboPieChart(
        'protocolComboChart',
        comboData
    );

    charts.ageDistChart = createBarChart(
        'ageDistChart',
        data.file_age_distribution,
        'Files',
        ['<24h', '1-7d', '7-30d', '>30d']
    );

    charts.sizePerPacketChart = createBarChart(
        'sizePerPacketChart',
        data.size_per_packet_distribution,
        'Files',
        ['<64B', '64-128B', '128-256B', '256-512B', '512B-1KB', '1KB-MTU', '>MTU', '(small sample)', '(no packets)']
    );
}

function renderScanModeStats(scanModeData, totalFiles) {
    const container = document.getElementById('scanModeStats');
    container.innerHTML = '';

    if (totalFiles === 0) {
        container.innerHTML = '<div class="scan-mode-empty">No scan data available</div>';
        return;
    }

    const modes = [
        { key: 'full', label: 'Full Scan', icon: '✓', colorClass: 'full' },
        { key: 'quick', label: 'Quick Scan', icon: '⚡', colorClass: 'quick' },
        { key: 'fast', label: 'Fast Scan', icon: '<i class="fa fa-rocket"></i>', colorClass: 'fast' }
    ];

    modes.forEach(mode => {
        const count = scanModeData[mode.key] || 0;
        const percentage = totalFiles > 0 ? ((count / totalFiles) * 100).toFixed(1) : 0;

        const modeCard = document.createElement('div');
        modeCard.className = `scan-mode-card scan-mode-${mode.colorClass}`;
        modeCard.innerHTML = `
            <div class="scan-mode-icon-large">
                <span class="scan-mode-badge scan-mode-badge-${mode.colorClass}">${mode.icon}</span>
            </div>
            <div class="scan-mode-details">
                <div class="scan-mode-label">${mode.label}</div>
                <div class="scan-mode-percentage">${percentage}%</div>
                <div class="scan-mode-count">${count.toLocaleString()} files</div>
            </div>
            <div class="scan-mode-bar-container">
                <div class="scan-mode-bar scan-mode-bar-${mode.colorClass}" style="width: ${percentage}%"></div>
            </div>
        `;
        container.appendChild(modeCard);
    });
}

function renderDirectoryTable(data) {
    const container = document.getElementById('directoryTable');
    container.innerHTML = '';

    // Build tree structure from flat paths
    const tree = buildDirectoryTree(data);
    
    // Render tree
    renderDirectoryTree(tree, container, 0);

    if (Object.keys(data).length === 0) {
        container.innerHTML = '<div class="table-row"><span class="table-cell-name">No data</span></div>';
    }
}

function buildDirectoryTree(data) {
    const tree = {};
    
    // Sort paths by depth (shorter first) and alphabetically
    const sortedPaths = Object.keys(data).sort((a, b) => {
        const depthA = a.split('/').length;
        const depthB = b.split('/').length;
        if (depthA !== depthB) return depthA - depthB;
        return a.localeCompare(b);
    });

    for (const path of sortedPaths) {
        const parts = path.split('/');
        let current = tree;
        
        for (let i = 0; i < parts.length; i++) {
            const part = parts[i] || '(root)';
            const currentPath = parts.slice(0, i + 1).join('/');
            
            if (!current[part]) {
                current[part] = {
                    count: data[currentPath] || 0,
                    path: currentPath,
                    children: {}
                };
            }
            current = current[part].children;
        }
    }

    return tree;
}

function renderDirectoryTree(tree, container, depth) {
    const entries = Object.entries(tree).sort((a, b) => a[0].localeCompare(b[0]));
    
    for (const [name, node] of entries) {
        const row = document.createElement('div');
        row.className = 'table-row tree-row';
        row.style.paddingLeft = `${depth * 20 + 16}px`;
        
        const hasChildren = Object.keys(node.children).length > 0;
        const icon = hasChildren ? '<i class="fa fa-folder tree-icon"></i>' : '<i class="fa fa-folder-o tree-icon"></i>';
        
        row.innerHTML = `
            <span class="table-cell-name tree-cell" title="${node.path}">
                ${icon}${name}
            </span>
            <span class="table-cell-count">${node.count}</span>
        `;
        
        if (hasChildren) {
            row.classList.add('expandable');
            const childContainer = document.createElement('div');
            childContainer.className = 'tree-children';
            
            row.addEventListener('click', (e) => {
                e.stopPropagation();
                row.classList.toggle('expanded');
                childContainer.classList.toggle('visible');
                const icon = row.querySelector('.tree-icon');
                if (row.classList.contains('expanded')) {
                    icon.className = 'fa fa-folder-open tree-icon';
                } else {
                    icon.className = 'fa fa-folder tree-icon';
                }
            });
            
            container.appendChild(row);
            container.appendChild(childContainer);
            renderDirectoryTree(node.children, childContainer, depth + 1);
        } else {
            container.appendChild(row);
        }
    }
}

function renderCaptureYearSection(data, tableRows = []) {
    const labels = tableRows.length
        ? tableRows.map(row => row.year)
        : Object.keys(data).sort((a, b) => {
            if (a === 'Unknown') return 1;
            if (b === 'Unknown') return -1;
            return a.localeCompare(b, undefined, { numeric: true });
        });
    const values = labels.map(year => data[year] || 0);
    const colors = labels.map((_, idx) => CHART_COLORS[idx % CHART_COLORS.length]);
    const borderColors = colors.map(color => color.replace('0.8', '1'));

    renderCaptureYearLegend(tableRows.length ? tableRows : labels.map(year => ({
        year,
        count: data[year] || 0,
        percentage: 0,
    })), colors);

    const ctx = document.getElementById('captureYearChart').getContext('2d');
    charts.captureYearChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Files',
                data: values,
                backgroundColor: colors,
                borderColor: borderColors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            onClick: (_event, elements) => {
                if (!elements.length) return;
                openCaptureYearModal(labels[elements[0].index]);
            },
            scales: {
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45,
                        autoSkip: true,
                        maxTicksLimit: 12
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title(context) {
                            return `Year ${context[0].label}`;
                        },
                        label(context) {
                            const row = tableRows.find(item => item.year === context.label);
                            const pct = row ? row.percentage : 0;
                            return ` ${context.parsed.y} files (${pct}%)`;
                        },
                        afterLabel(context) {
                            return 'Click to view files';
                        }
                    }
                }
            }
        }
    });

    populateCaptureYearSelect(labels);
}

function renderCaptureYearLegend(rows, colors) {
    const legendContainer = document.getElementById('captureYearLegendList');
    if (!legendContainer) return;

    legendContainer.innerHTML = '';
    const sortedRows = [...rows].sort((a, b) => b.count - a.count);

    sortedRows.forEach((row, idx) => {
        const colorIndex = rows.findIndex(item => item.year === row.year);
        const color = colors[colorIndex >= 0 ? colorIndex : idx % colors.length];
        const item = document.createElement('div');
        item.className = 'legend-item legend-item-compact capture-year-legend-item';
        item.style.borderLeftColor = color;
        item.innerHTML = `
            <div class="legend-item-header">
                <span class="legend-item-label">${row.year}</span>
                <span class="legend-item-count">${row.count}</span>
            </div>
            <button type="button" class="capture-year-view-btn" data-year="${row.year}" title="View files from ${row.year}">
                <i class="fa fa-folder-open"></i> View files
            </button>
        `;

        item.querySelector('.capture-year-view-btn').addEventListener('click', (event) => {
            event.stopPropagation();
            openCaptureYearModal(row.year);
        });
        item.addEventListener('click', () => openCaptureYearModal(row.year));

        legendContainer.appendChild(item);
    });
}

function initCaptureYearModal() {
    const modal = document.getElementById('captureYearModal');
    const browseBtn = document.getElementById('captureYearBrowseBtn');
    const closeBtn = document.getElementById('captureYearModalClose');
    const backdrop = document.getElementById('captureYearModalBackdrop');
    const select = document.getElementById('captureYearSelect');

    browseBtn?.addEventListener('click', () => {
        const defaultYear = select?.value || captureYearTableData[0]?.year;
        openCaptureYearModal(defaultYear);
    });
    closeBtn?.addEventListener('click', closeCaptureYearModal);
    backdrop?.addEventListener('click', closeCaptureYearModal);
    select?.addEventListener('change', () => loadCaptureYearFiles(select.value));

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && !modal.classList.contains('hidden')) {
            closeCaptureYearModal();
        }
    });
}

function populateCaptureYearSelect(years) {
    const select = document.getElementById('captureYearSelect');
    if (!select) return;

    select.innerHTML = '';
    years.forEach((year) => {
        const option = document.createElement('option');
        option.value = year;
        option.textContent = year;
        select.appendChild(option);
    });
}

function openCaptureYearModal(year) {
    if (!year) return;

    const modal = document.getElementById('captureYearModal');
    const select = document.getElementById('captureYearSelect');
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';

    if (select && [...select.options].some(option => option.value === year)) {
        select.value = year;
    }

    loadCaptureYearFiles(year);
}

function closeCaptureYearModal() {
    document.getElementById('captureYearModal')?.classList.add('hidden');
    document.body.style.overflow = '';
}

async function loadCaptureYearFiles(year) {
    const loading = document.getElementById('captureYearFilesLoading');
    const list = document.getElementById('captureYearFilesList');
    const countEl = document.getElementById('captureYearFileCount');

    if (!year || !list) return;

    loading?.classList.remove('hidden');
    list.innerHTML = '';
    if (countEl) countEl.textContent = '';

    try {
        const response = await axios.get(`${SERVER}${API_PATH.CAPTURE_YEAR_FILES_PATH}`, {
            params: { year }
        });
        const files = response.data.files || [];
        if (countEl) {
            countEl.textContent = `${files.length} file${files.length === 1 ? '' : 's'}`;
        }

        if (!files.length) {
            list.innerHTML = '<div class="capture-year-empty">No files found for this year.</div>';
            return;
        }

        files.forEach((file) => {
            const row = document.createElement('div');
            row.className = 'capture-year-file-row';
            row.innerHTML = `
                <div class="capture-year-file-name" title="${file.path}">${file.filename}</div>
                <div class="capture-year-file-meta">${formatCaptureStart(file.capture_start)}</div>
                <div class="capture-year-file-path" title="${file.path}">${file.path}</div>
            `;
            list.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading capture year files:', error);
        list.innerHTML = '<div class="capture-year-empty">Failed to load files for this year.</div>';
    } finally {
        loading?.classList.add('hidden');
    }
}

function formatCaptureStart(value) {
    if (!value) return 'Capture time unknown';
    const numeric = Number(value);
    if (!Number.isNaN(numeric)) {
        const date = new Date(numeric * 1000);
        if (!Number.isNaN(date.getTime())) return date.toLocaleString();
    }
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date.toLocaleString();
    return value;
}

function renderExtensionTable(data) {
    const container = document.getElementById('extensionTable');
    container.innerHTML = '';

    // Sort by count descending
    const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]);

    sorted.forEach(([ext, count]) => {
        const row = document.createElement('div');
        row.className = 'table-row';
        row.innerHTML = `
            <span class="table-cell-name" title="${ext}">${ext}</span>
            <span class="table-cell-count">${count}</span>
        `;
        container.appendChild(row);
    });

    if (sorted.length === 0) {
        container.innerHTML = '<div class="table-row"><span class="table-cell-name">No data</span></div>';
    }
}

function createBarChart(canvasId, data, label, orderedLabels = null) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    const labels = orderedLabels || Object.keys(data).sort();
    const values = labels.map(l => data[l] || 0);

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: label,
                data: values,
                backgroundColor: 'rgba(102, 126, 234, 0.6)',
                borderColor: 'rgba(102, 126, 234, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

function createHorizontalBarChart(canvasId, data, label) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    // Sort by count and take top 15
    const sorted = Object.entries(data)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 15);
    
    const labels = sorted.map(([k, v]) => k);
    const values = sorted.map(([k, v]) => v);

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: label,
                data: values,
                backgroundColor: 'rgba(118, 75, 162, 0.6)',
                borderColor: 'rgba(118, 75, 162, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

function sortEntriesByValueDesc(entries) {
    const list = Array.isArray(entries)
        ? [...entries]
        : Object.entries(entries || {});
    return list.sort((a, b) => {
        const valueDiff = b[1] - a[1];
        if (valueDiff !== 0) return valueDiff;
        return String(a[0]).localeCompare(String(b[0]), undefined, { numeric: true });
    });
}

function preparePieSlices(data, maxItems = 5) {
    const sorted = sortEntriesByValueDesc(data);

    const topEntries = sorted.filter(([, count], idx) => count > 1 && idx < maxItems);
    const remainder = sorted.filter(([, count], idx) => count === 1 || idx >= maxItems);
    const otherCount = remainder.reduce((sum, [, count]) => sum + count, 0);

    const finalEntries = [...topEntries];
    if (otherCount > 0) {
        finalEntries.push(['Others', otherCount]);
    }

    return {
        finalEntries: sortEntriesByValueDesc(finalEntries),
        remainder,
    };
}

function formatDiversityLabel(key) {
    if (key === 'Others') return 'Others';
    const n = Number(key);
    return `${n} protocol${n === 1 ? '' : 's'}`;
}

function getDiversitySliceCombos(sliceKey, details, remainder) {
    if (sliceKey === 'Others') {
        const combos = [];
        for (const [divKey] of remainder) {
            const bucket = details[divKey] || [];
            bucket.forEach((item) => combos.push({ ...item, diversity: divKey }));
        }
        combos.sort((a, b) => b.count - a.count);
        return combos;
    }
    return details[sliceKey] || [];
}

function buildLegendHoverPanel(lines) {
    if (!lines.length) return '';
    const html = lines
        .map((line) => `<div class="legend-hover-line">${line}</div>`)
        .join('');
    return `<div class="legend-hover-panel">${html}</div>`;
}

function truncateLegendLabel(text, maxLen = 42) {
    if (!text || text.length <= maxLen) return text;
    return `${text.slice(0, maxLen - 3)}...`;
}

function buildComboDetailLines(combos, maxLines = 6) {
    if (!combos.length) {
        return [' (no protocol detail)'];
    }
    const lines = combos.slice(0, maxLines).map(
        (item) => ` • ${item.protocols} (${item.count} file${item.count > 1 ? 's' : ''})`
    );
    if (combos.length > maxLines) {
        lines.push(` • … +${combos.length - maxLines} more`);
    }
    return lines;
}

function createPieChart(canvasId, data, label, details = {}) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    const { finalEntries, remainder } = preparePieSlices(data, 5);

    const labels = finalEntries.map(([key]) => formatDiversityLabel(key));
    const values = finalEntries.map(([, count]) => count);
    const sliceKeys = finalEntries.map(([key]) => key);

    const sliceCombosMap = Object.fromEntries(
        sliceKeys.map((key) => [formatDiversityLabel(key), getDiversitySliceCombos(key, details, remainder)])
    );

    const colors = [
        'rgba(102, 126, 234, 0.8)',
        'rgba(118, 75, 162, 0.8)',
        'rgba(16, 185, 129, 0.8)',
        'rgba(245, 158, 11, 0.8)',
        'rgba(239, 68, 68, 0.8)',
        'rgba(59, 130, 246, 0.8)',
        'rgba(168, 85, 247, 0.8)',
        'rgba(236, 72, 153, 0.8)',
        'rgba(20, 184, 166, 0.8)',
        'rgba(251, 146, 60, 0.8)',
    ];

    const legendContainer = document.getElementById('diversityLegendList');
    if (legendContainer) {
        legendContainer.innerHTML = '';
        finalEntries.forEach(([key, count], idx) => {
            const color = colors[idx % colors.length];
            const displayLabel = formatDiversityLabel(key);
            const combos = getDiversitySliceCombos(key, details, remainder);
            const hoverLines = combos.map(
                (item) => `${item.protocols} (${item.count} file${item.count > 1 ? 's' : ''})`
            );

            const item = document.createElement('div');
            item.className = 'legend-item legend-item-compact';
            item.style.borderLeftColor = color;
            item.innerHTML = `
                <div class="legend-item-header">
                    <span class="legend-item-label">${displayLabel}</span>
                    <span class="legend-item-count">${count}</span>
                </div>
                ${hoverLines.length ? buildLegendHoverPanel(hoverLines) : ''}
            `;
            legendContainer.appendChild(item);
        });
    }

    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels,
            datasets: [{
                label: label,
                data: values,
                backgroundColor: colors,
                borderWidth: 1,
                borderColor: '#ffffff2f'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title: (context) => context[0].label,
                        label: (context) => {
                            const count = context.raw;
                            const total = context.dataset.data.reduce((sum, n) => sum + n, 0);
                            const pct = ((count / total) * 100).toFixed(1);
                            const combos = sliceCombosMap[context.label] || [];
                            return [
                                ` ${count} files (${pct}%)`,
                                ' ─────────────────',
                                ...buildComboDetailLines(combos, 10),
                            ];
                        }
                    }
                }
            }
        }
    });
}

function createProtocolComboPieChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');

    const { finalEntries, remainder } = preparePieSlices(data, 5);

    const comboLabels = finalEntries.map(([combo]) => combo);
    const comboValues = finalEntries.map(([, value]) => value);

    const colors = [
        'rgba(102, 126, 234, 0.8)',
        'rgba(118, 75, 162, 0.8)',
        'rgba(16, 185, 129, 0.8)',
        'rgba(245, 158, 11, 0.8)',
        'rgba(239, 68, 68, 0.8)',
        'rgba(59, 130, 246, 0.8)',
        'rgba(168, 85, 247, 0.8)',
        'rgba(236, 72, 153, 0.8)',
        'rgba(20, 184, 166, 0.8)',
        'rgba(251, 146, 60, 0.8)',
    ];

    // Render legend items
    const legendContainer = document.getElementById('protocolComboLegendList');
    if (legendContainer) {
        legendContainer.innerHTML = '';
        comboLabels.forEach((lbl, idx) => {
            const color = colors[idx % colors.length];
            const count = comboValues[idx];
            const hoverLines =
                lbl === 'Others'
                    ? remainder.map(([combo, n]) => `${combo} (${n} file${n > 1 ? 's' : ''})`)
                    : [lbl];

            const compactLabel = lbl === 'Others' ? 'Others' : truncateLegendLabel(lbl, 36);

            const item = document.createElement('div');
            item.className = 'legend-item legend-item-compact';
            item.style.borderLeftColor = color;
            item.innerHTML = `
                <div class="legend-item-header">
                    <span class="legend-item-label">${compactLabel}</span>
                    <span class="legend-item-count">${count}</span>
                </div>
                ${buildLegendHoverPanel(hoverLines)}
            `;
            legendContainer.appendChild(item);
        });
    }

    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels: comboLabels,
            datasets: [{
                data: comboValues,
                backgroundColor: colors,
                borderWidth: 1,
                borderColor: '#ffffff2f'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        title: (context) => {
                            return context[0].label;
                        },
                        label: (context) => {
                            const count = context.raw;
                            const total = context.dataset.data.reduce((sum, count) => sum + count, 0);
                            const pct = ((count / total) * 100).toFixed(1);

                            // Default tooltip for normal slices
                            // Default tooltip for normal slices
                            if (context.label !== 'Others') {
                                return ` ${count} files (${pct}%)`;
                            }

                            const lines = [
                                ` ${count} files (${pct}%)`,
                                ` ─────────────────`,
                                ...remainder.map(([lbl, n]) => {
                                    const short = lbl.length > 40 ? `${lbl.slice(0, 37)}...` : lbl;
                                    return ` • ${short} (${n} file${n > 1 ? 's' : ''})`;
                                }),
                            ];

                            return lines;
                        }
                    }
                }
            }
        }
    })
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (pollInterval) {
        clearInterval(pollInterval);
    }
});
