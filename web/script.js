let scanData = [];
let alertData = [];
let detectedNetwork = { gateway: '192.168.1.1', subnet: '192.168.1.0/24', base: '192.168.1' };

const PORT_PRESETS = {
    common: [21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 8080],
    web: [80, 443, 8080, 8443, 3000, 5000],
    full: Array.from({ length: 1024 }, (_, i) => i + 1)
};

function detectNetwork() {
    fetch('/api/network-info')
        .then(response => response.json())
        .then(data => {
            if (data.gateway && data.network) {
                const parts = data.gateway.split('.');
                detectedNetwork.gateway = data.gateway;
                detectedNetwork.subnet = data.network;
                detectedNetwork.base = parts.slice(0, 3).join('.');
            }
        })
        .catch(() => {});
}

function getFriendlyName(ip) {
    if (ip === '127.0.0.1') return 'Your Computer (Localhost)';
    if (ip === detectedNetwork.gateway) return 'Router (' + ip + ')';
    if (ip.endsWith('.1')) return 'Router (' + ip + ')';
    if (ip.startsWith(detectedNetwork.base + '.')) return 'Local Device (' + ip + ')';
    if (ip.startsWith('192.168.')) return 'Local Device (' + ip + ')';
    if (ip.startsWith('10.0.')) return 'Local Device (' + ip + ')';
    return ip;
}

function isDuplicateScan(newScan, existingScan) {
    if (newScan.ip !== existingScan.ip) return false;
    if (newScan.ports.length !== existingScan.ports.length) return false;
    const sortedNew = [...newScan.ports].sort((a, b) => a - b);
    const sortedExisting = [...existingScan.ports].sort((a, b) => a - b);
    if (!sortedNew.every((port, i) => port === sortedExisting[i])) return false;
    const newTime = new Date(newScan.timestamp).getTime();
    const existingTime = new Date(existingScan.timestamp).getTime();
    return (newTime - existingTime) < 5 * 60 * 1000;
}

function removeDuplicates(scans) {
    const cleaned = [];
    for (let i = scans.length - 1; i >= 0; i--) {
        const current = scans[i];
        let isDupe = false;
        for (const kept of cleaned) {
            if (isDuplicateScan(current, kept)) { isDupe = true; break; }
        }
        if (!isDupe) cleaned.push(current);
    }
    return cleaned.reverse();
}

window.onload = function () {
    console.log('Dashboard ready!');
    detectNetwork();
    refreshData();

    // Hide remote access panel if viewing from PC2 (locally)
    if (!window.IS_REMOTE_VIEWER) {
        document.querySelectorAll('.control-panel').forEach(p => {
            const h2 = p.querySelector('h2');
            if (h2 && h2.textContent.includes('Remote Access')) {
                p.style.display = 'none';
            }
        });
    }
};

function refreshData() {
    fetch('/api/scans')
        .then(response => response.json())
        .then(data => {
            scanData = removeDuplicates(data.scans || []);
            updateDashboard();
        })
        .catch(() => {});

    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            alertData = data.alerts || [];
            updateAlerts();
        })
        .catch(() => {});
}

function updateDashboard() {
    document.getElementById('total-scans').textContent = scanData.length;
    const uniqueIPs = new Set(scanData.map(s => s.ip));
    document.getElementById('unique-hosts').textContent = uniqueIPs.size;
    let totalPorts = 0;
    scanData.forEach(scan => { totalPorts += scan.ports.length; });
    document.getElementById('open-ports').textContent = totalPorts;

    let scanList = document.getElementById('scan-list');
    if (scanData.length === 0) {
        scanList.innerHTML = '<p class="empty-state">No scans yet. Click a button above to start scanning.</p>';
        return;
    }
    scanList.innerHTML = '';
    let recentScans = [...scanData].reverse().slice(0, 20);
    recentScans.forEach(scan => {
        let item = document.createElement('div');
        item.className = 'scan-item';
        let header = document.createElement('div');
        header.className = 'scan-header';
        let ip = document.createElement('span');
        ip.className = 'scan-ip';
        ip.textContent = getFriendlyName(scan.ip);
        let time = document.createElement('span');
        time.className = 'scan-time';
        time.textContent = scan.timestamp || 'Unknown';
        header.appendChild(ip);
        header.appendChild(time);
        let ports = document.createElement('div');
        ports.className = 'scan-ports';
        if (scan.ports.length === 0) {
            ports.innerHTML = '<span style="color: #8b949e;">No open ports found</span>';
        } else {
            scan.ports.forEach(port => {
                let badge = document.createElement('span');
                badge.className = 'port-badge';
                badge.textContent = `Port ${port}`;
                ports.appendChild(badge);
            });
        }
        item.appendChild(header);
        item.appendChild(ports);
        scanList.appendChild(item);
    });
}

function updateAlerts() {
    let alertsList = document.getElementById('alerts-list');
    if (!alertsList) return;
    if (alertData.length === 0) {
        alertsList.innerHTML = '<p class="empty-state">No security alerts detected.</p>';
        return;
    }
    const uniqueAlerts = new Set();
    const uniqueAlertData = [];
    alertData.forEach(alert => {
        const key = `${alert.ip}:${alert.port}:${alert.level}:${alert.message}`;
        if (!uniqueAlerts.has(key)) { uniqueAlerts.add(key); uniqueAlertData.push(alert); }
    });
    alertsList.innerHTML = '';
    uniqueAlertData.forEach(alert => {
        let item = document.createElement('div');
        item.className = `alert-item alert-${alert.level.toLowerCase()}`;
        let header = document.createElement('div');
        header.className = 'alert-header';
        header.textContent = `[${alert.level}] ${getFriendlyName(alert.ip)} - Port ${alert.port}`;
        let message = document.createElement('div');
        message.className = 'alert-message';
        message.textContent = alert.message;
        item.appendChild(header);
        item.appendChild(message);
        alertsList.appendChild(item);
    });
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => notification.classList.add('show'), 10);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function quickScan(target, preset = 'common') {
    let targetIP;
    let ports = PORT_PRESETS[preset] || PORT_PRESETS.common;
    if (target === 'localhost') targetIP = '127.0.0.1';
    else if (target === 'router') targetIP = detectedNetwork.gateway;
    else if (target === 'network') { targetIP = detectedNetwork.subnet; showNotification('Network scan will take a few minutes...', 'info'); }
    else targetIP = target;
    triggerScan(targetIP, ports);
}

function customScan() {
    const targetIP = document.getElementById('target-ip').value.trim();
    const portsInput = document.getElementById('target-ports').value.trim();
    if (!targetIP) { showNotification('Please enter a target address', 'error'); return; }
    let ports;
    if (portsInput) {
        ports = portsInput.split(',').map(p => parseInt(p.trim())).filter(p => p > 0 && p <= 65535);
        if (ports.length === 0) { showNotification('Please enter valid port numbers', 'error'); return; }
    } else {
        ports = PORT_PRESETS.common;
    }
    triggerScan(targetIP, ports);
}

function triggerScan(target, ports) {
    const allButtons = document.querySelectorAll('button');
    allButtons.forEach(btn => { btn.disabled = true; btn.style.opacity = '0.6'; });
    showNotification(`Scanning ${getFriendlyName(target)}...`, 'info');
    fetch('/api/scan/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, ports })
    })
    .then(response => response.json())
    .then(() => {
        showNotification('Scan complete!', 'success');
        setTimeout(refreshData, 1500);
    })
    .finally(() => {
        setTimeout(() => {
            allButtons.forEach(btn => { btn.disabled = false; btn.style.opacity = '1'; });
        }, 2000);
    });
}

function clearData() {
    if (!confirm('Are you sure you want to clear all scan history?')) return;
    fetch('/api/clear', { method: 'POST' })
        .then(response => response.json())
        .then(() => {
            showNotification('History cleared', 'success');
            scanData = []; alertData = [];
            updateDashboard(); updateAlerts();
        });
}

setInterval(refreshData, 10000);

// Remote access banner
function loadRemoteAccessInfo() {
    fetch('/api/info')
        .then(r => r.json())
        .then(data => {
            if (data.host && data.host !== '127.0.0.1' && data.host !== 'unknown') {
                const url = `http://${data.host}:${data.port}`;
                document.getElementById('remote-url').textContent = url;
                document.getElementById('remote-access-banner').style.display = 'flex';
                window._remoteURL = url;
            }
        })
        .catch(() => {});
}

function copyRemoteURL() {
    if (window._remoteURL) {
        navigator.clipboard.writeText(window._remoteURL)
            .then(() => showNotification('URL copied to clipboard!', 'success'))
            .catch(() => { prompt('Copy this URL:', window._remoteURL); });
    }
}

loadRemoteAccessInfo();

// ── REMOTE CONTROL ────────────────────────────────────────────────────────────

function shutdownSentinel() {
    if (!confirm('Are you sure you want to shut down SentinelNet on the remote machine?')) return;
    fetch('/api/shutdown', { method: 'POST' })
        .then(() => showNotification('SentinelNet is shutting down...', 'info'))
        .catch(() => showNotification('Shutdown signal sent.', 'info'));
}

function restartSentinel() {
    if (!confirm('Restart SentinelNet on the remote machine?')) return;
    fetch('/api/restart', { method: 'POST' })
        .then(() => {
            showNotification('Restarting... reconnecting in 5 seconds.', 'info');
            setTimeout(() => location.reload(), 5000);
        })
        .catch(() => showNotification('Restart signal sent.', 'info'));
}

function refreshStatus() {
    fetch('/api/status')
        .then(r => r.json())
        .then(data => {
            const badge = document.getElementById('uptime-badge');
            if (badge) {
                const h = Math.floor(data.uptime / 3600);
                const m = Math.floor((data.uptime % 3600) / 60);
                const s = data.uptime % 60;
                const upStr = h > 0 ? `${h}h ${m}m ${s}s` : m > 0 ? `${m}m ${s}s` : `${s}s`;
                badge.textContent = `| Uptime: ${upStr} | Host: ${data.host}:${data.port} | v${data.version}`;
            }
        })
        .catch(() => {});
}

setInterval(refreshStatus, 5000);
refreshStatus();

// ── LOG VIEWER ────────────────────────────────────────────────────────────────

let logAutoRefreshTimer = null;

function refreshLogList() {
    fetch('/api/logs')
        .then(r => r.json())
        .then(data => {
            const select = document.getElementById('log-file-select');
            const current = select.value;
            select.innerHTML = '<option value="">-- Select a log file --</option>';
            (data.files || []).sort().reverse().forEach(f => {
                const opt = document.createElement('option');
                opt.value = f; opt.textContent = f;
                if (f === current) opt.selected = true;
                select.appendChild(opt);
            });
            if (!current && data.files && data.files.length > 0) {
                select.value = data.files.sort().reverse()[0];
                loadLogFile();
            }
        })
        .catch(() => {});
}

function loadLogFile() {
    const file = document.getElementById('log-file-select').value;
    if (!file) return;
    fetch(`/api/logs/read?file=${encodeURIComponent(file)}`)
        .then(r => r.json())
        .then(data => {
            const viewer = document.getElementById('log-viewer');
            if (data.error) { viewer.innerHTML = `<span style="color:#ff3e3e;">${data.error}</span>`; return; }
            const lines = data.content.split('\\n').map(line => {
                if (line.includes('CRITICAL')) return `<span style="color:#ff3e3e;font-weight:bold;">${line}</span>`;
                if (line.includes('HIGH'))     return `<span style="color:#ff6b35;">${line}</span>`;
                if (line.includes('MEDIUM'))   return `<span style="color:#ffa500;">${line}</span>`;
                if (line.includes('ERROR'))    return `<span style="color:#ff3e3e;">${line}</span>`;
                if (line.includes('ALERT') || line.includes('SECURITY')) return `<span style="color:#ffd700;">${line}</span>`;
                if (line.includes('started') || line.includes('shutdown')) return `<span style="color:#58a6ff;">${line}</span>`;
                return `<span style="color:#c9d1d9;">${line}</span>`;
            });
            viewer.innerHTML = lines.join('\n');
            if (document.getElementById('log-autoscroll').checked) viewer.scrollTop = viewer.scrollHeight;
        })
        .catch(() => {});
}

function toggleLogAutoRefresh() {
    const enabled = document.getElementById('log-autorefresh').checked;
    if (enabled) { loadLogFile(); logAutoRefreshTimer = setInterval(loadLogFile, 3000); }
    else { clearInterval(logAutoRefreshTimer); logAutoRefreshTimer = null; }
}

refreshLogList();

// ── REMOTE ACCESS ─────────────────────────────────────────────────────────────

let screenshotRefreshTimer = null;
let lastScreenshotWidth = 1920;
let lastScreenshotHeight = 1080;

function takeScreenshot() {
    fetch('/api/screenshot')
        .then(r => r.json())
        .then(data => {
            lastScreenshotWidth = data.width;
            lastScreenshotHeight = data.height;
            document.getElementById('screenshot-img').src = 'data:image/bmp;base64,' + data.data;
            document.getElementById('screenshot-container').style.display = 'block';
            document.getElementById('screenshot-time').textContent = 'Last: ' + new Date().toLocaleTimeString();
        })
        .catch(() => showNotification('Screenshot failed', 'error'));
}

function toggleScreenshotRefresh() {
    const enabled = document.getElementById('screenshot-autorefresh').checked;
    if (enabled) { takeScreenshot(); screenshotRefreshTimer = setInterval(takeScreenshot, 3000); }
    else { clearInterval(screenshotRefreshTimer); screenshotRefreshTimer = null; }
}

function handleScreenshotClick(event) {
    const img = event.target;
    const rect = img.getBoundingClientRect();
    const x = Math.round((event.clientX - rect.left) * (lastScreenshotWidth / rect.width));
    const y = Math.round((event.clientY - rect.top) * (lastScreenshotHeight / rect.height));
    fetch('/api/click', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ x, y })
    })
    .then(() => showNotification(`Clicked (${x}, ${y}) on PC2`, 'success'))
    .catch(() => showNotification('Click failed', 'error'));
}

function openRemoteURL() {
    const url = document.getElementById('remote-url-input').value.trim();
    if (!url) { showNotification('Enter a URL first', 'error'); return; }
    fetch('/api/openurl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    })
    .then(() => showNotification(`Opened ${url} on PC2`, 'success'))
    .catch(() => showNotification('Failed to open URL', 'error'));
}

function openRemoteFile() {
    const path = document.getElementById('remote-file-input').value.trim();
    if (!path) { showNotification('Enter a file path first', 'error'); return; }
    fetch('/api/openfile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path })
    })
    .then(() => showNotification('Opened file on PC2', 'success'))
    .catch(() => showNotification('Failed to open file', 'error'));
}

// ── ONLINE NOTIFICATION ───────────────────────────────────────────────────────

let pc2WasOnline = false;

function checkPC2Online() {
    fetch('/api/online')
        .then(r => r.json())
        .then(data => {
            if (data.online && !pc2WasOnline) {
                pc2WasOnline = true;
                if (Notification.permission === 'granted') {
                    new Notification('SentinelNet', { body: `PC2 (${data.host}) is now online!` });
                }
                showNotification(`PC2 (${data.host}) is online!`, 'success');
            }
        })
        .catch(() => { if (pc2WasOnline) { pc2WasOnline = false; showNotification('PC2 went offline', 'info'); } });
}

if (Notification.permission === 'default') Notification.requestPermission();
setInterval(checkPC2Online, 10000);
checkPC2Online();