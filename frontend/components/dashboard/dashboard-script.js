import { SERVER, API_PATH } from "../constant.js";

const loadingIndicator = document.getElementById('loadingIndicator');
const errorMessage = document.getElementById('errorMessage');
const dashboardContent = document.getElementById('dashboardContent');
const refreshBtn = document.getElementById('refreshBtn');
const lastUpdatedEl = document.getElementById('lastUpdated');

let charts = {};
let pollInterval = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    loadDashboardData();
    
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
        'Protocol Count'
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

function createPieChart(canvasId, data, label) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    const labels = Object.keys(data).sort((a, b) => parseInt(a) - parseInt(b));
    const values = labels.map(l => data[l] || 0);

    const colors = [
        'rgba(102, 126, 234, 0.8)',
        'rgba(118, 75, 162, 0.8)',
        'rgba(16, 185, 129, 0.8)',
        'rgba(245, 158, 11, 0.8)',
        'rgba(239, 68, 68, 0.8)',
        'rgba(59, 130, 246, 0.8)',
        'rgba(168, 85, 247, 0.8)',
    ];

    // Render custom legend list
    const legendContainer = document.getElementById('diversityLegendList');
    if (legendContainer) {
        legendContainer.innerHTML = '';
        labels.forEach((lbl, idx) => {
            const color = colors[idx % colors.length];
            const item = document.createElement('div');
            item.className = 'legend-item';
            item.style.borderLeftColor = color;
            item.innerHTML = `
                <span class="legend-item-label">${lbl} protocols</span>
                <span class="legend-item-count">${values[idx]}</span>
            `;
            legendContainer.appendChild(item);
        });
    }

    return new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels.map(l => `${l} protocols`),
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
                }
            }
        }
    });
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (pollInterval) {
        clearInterval(pollInterval);
    }
});
