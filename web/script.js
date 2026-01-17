let scanData = [];
let alertData = [];
let isScanning = false;

const PORT_PRESETS = {
    common: [21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 8080],
    web: [80, 443, 8080, 8443, 3000, 5000],
    full: Array.from({ length: 1024 }, (_, i) => i + 1)
};


function refreshData() {
    fetch('/api/scans')
        .then(r => r.json())
        .then(data => {
            scanData = Array.isArray(data.scans) ? data.scans : [];
            updateDashboard();
        })
        .catch(err => console.error('Scan fetch error:', err));

    fetch('/api/alerts')
        .then(r => r.json())
        .then(data => {
            alertData = Array.isArray(data.alerts) ? data.alerts : [];
            updateAlerts();
        })
        .catch(err => console.error('Alert fetch error:', err));
}


function updateDashboard() {
    const totalScansEl = document.getElementById('total-scans');
    const uniqueHostsEl = document.getElementById('unique-hosts');
    const openPortsEl = document.getElementById('open-ports');
    const scanList = document.getElementById('scan-list');

    if (!scanList) return;

    totalScansEl && (totalScansEl.textContent = scanData.length);

    const latestByIp = new Map();
    scanData.forEach(scan => {
        if (scan && scan.ip) latestByIp.set(scan.ip, scan);
    });

    uniqueHostsEl && (uniqueHostsEl.textContent = latestByIp.size);

    let totalPorts = 0;
    latestByIp.forEach(scan => {
        const ports = Array.isArray(scan.ports) ? scan.ports : [];
        totalPorts += ports.length;
    });

    openPortsEl && (openPortsEl.textContent = totalPorts);

    if (scanData.length === 0) {
        scanList.innerHTML = '<p class="empty-state">No scans yet.</p>';
        return;
    }

    scanList.innerHTML = '';
    const recentScans = [...scanData].reverse().slice(0, 20);

    recentScans.forEach(scan => {
        const ports = Array.isArray(scan.ports) ? scan.ports : [];

        const item = document.createElement('div');
        item.className = 'scan-item';

        const header = document.createElement('div');
        header.className = 'scan-header';

        header.innerHTML = `
            <span class="scan-ip">${scan.ip || 'Unknown'}</span>
            <span class="scan-time">${scan.timestamp || 'Unknown'}</span>
        `;

        const portsDiv = document.createElement('div');
        portsDiv.className = 'scan-ports';

        if (ports.length === 0) {
            portsDiv.innerHTML = '<span style="color:#8b949e;">No open ports</span>';
        } else {
            ports.forEach(p => {
                const badge = document.createElement('span');
                badge.className = 'port-badge';
                badge.textContent = `Port ${p}`;
                portsDiv.appendChild(badge);
            });
        }

        item.appendChild(header);
        item.appendChild(portsDiv);
        scanList.appendChild(item);
    });
}


function updateAlerts() {
    const alertsList = document.getElementById('alerts-list');
    if (!alertsList) return;

    if (alertData.length === 0) {
        alertsList.innerHTML = '<p class="empty-state">No security alerts.</p>';
        return;
    }

    const seen = new Set();
    alertsList.innerHTML = '';

    alertData.forEach(alert => {
        const key = `${alert.ip}-${alert.port}-${alert.level}-${alert.message}`;
        if (seen.has(key)) return;
        seen.add(key);

        const item = document.createElement('div');
        item.className = `alert-item alert-${alert.level?.toLowerCase() || 'info'}`;

        item.innerHTML = `
            <div class="alert-header">[${alert.level}] ${alert.ip}:${alert.port}</div>
            <div class="alert-message">${alert.message}</div>
        `;

        alertsList.appendChild(item);
    });
}


function showNotification(message, type = 'info') {
    const note = document.createElement('div');
    note.className = `notification notification-${type}`;
    note.textContent = message;

    document.body.appendChild(note);
    setTimeout(() => note.classList.add('show'), 10);

    setTimeout(() => {
        note.classList.remove('show');
        setTimeout(() => note.remove(), 300);
    }, 3000);
}


function quickScan(target, preset = 'common') {
    if (isScanning) return showNotification('Scan already running', 'warning');

    const ports = PORT_PRESETS[preset] || PORT_PRESETS.common;

    const targets = {
        localhost: '127.0.0.1',
        router: '192.168.1.1',
        network: '192.168.1.0/24'
    };

    if (target === 'network') {
        showNotification('Network scan started (this may take time)', 'info');
    }

    triggerScan(targets[target] || target, ports);
}

function customScan() {
    if (isScanning) return showNotification('Scan already running', 'warning');

    const ip = document.getElementById('target-ip')?.value.trim();
    const portsRaw = document.getElementById('target-ports')?.value.trim();

    if (!ip) return showNotification('Target IP required', 'error');

    let ports = PORT_PRESETS.common;
    if (portsRaw) {
        ports = portsRaw
            .split(',')
            .map(p => parseInt(p.trim()))
            .filter(p => p > 0 && p <= 65535);

        if (!ports.length) return showNotification('Invalid ports', 'error');
    }

    triggerScan(ip, ports);
}

function triggerScan(target, ports) {
    if (isScanning) return;

    isScanning = true;
    toggleScanButtons(true);

    showNotification(`Scan started for ${target}`, 'info');

    fetch('/api/scan/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, ports })
    })
    .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
    })
    .then(() => {
        showNotification('Scan finished', 'success');
        refreshData();
    })
    .finally(() => {
        isScanning = false;
        toggleScanButtons(false);
    });
}

function toggleScanButtons(disabled) {
    document.querySelectorAll('.scan-button').forEach(btn => {
        btn.disabled = disabled;
        btn.style.opacity = disabled ? '0.6' : '1';
        btn.style.cursor = disabled ? 'not-allowed' : 'pointer';
    });
}


function clearData() {
    if (!confirm('Clear all scan data?')) return;

    fetch('/api/clear', { method: 'POST' })
        .then(() => {
            scanData = [];
            alertData = [];
            updateDashboard();
            updateAlerts();
            showNotification('Data cleared', 'success');
        })
        .catch(() => showNotification('Clear failed', 'error'));
}


setInterval(refreshData, 10000);
window.onload = refreshData;