let scanData = [];
let alertData = [];
let detectedNetwork = { gateway: '192.168.1.1', subnet: '192.168.1.0/24', base: '192.168.1' };

const PORT_PRESETS = {
    common: [21, 22, 23, 25, 80, 135, 139, 443, 445, 3306, 3389, 8080],
    web: [80, 443, 8080, 8443, 3000, 5000],
    full: Array.from({ length: 1024 }, (_, i) => i + 1)
};

// Detect the most likely network from available interfaces
function detectNetwork() {
    fetch('/api/network-info')
        .then(response => response.json())
        .then(data => {
            if (data.gateway && data.network) {
                const parts = data.gateway.split('.');
                detectedNetwork.gateway = data.gateway;
                detectedNetwork.subnet = data.network;
                detectedNetwork.base = parts.slice(0, 3).join('.');
                console.log('Network detected:', detectedNetwork);
            }
        })
        .catch(error => {
            console.log('Using default network settings');
        });
}

// Get friendly name for IP
function getFriendlyName(ip) {
    if (ip === '127.0.0.1') return 'Your Computer (Localhost)';
    if (ip === detectedNetwork.gateway) return 'Router (' + ip + ')';
    if (ip.endsWith('.1')) return 'Router (' + ip + ')';
    if (ip.startsWith(detectedNetwork.base + '.')) return 'Local Device (' + ip + ')';
    if (ip.startsWith('192.168.')) return 'Local Device (' + ip + ')';
    if (ip.startsWith('10.0.')) return 'Local Device (' + ip + ')';
    return ip;
}

// Check if two scans are duplicates (same IP, same ports, within 5 minutes)
function isDuplicateScan(newScan, existingScan) {
    // Must be same IP
    if (newScan.ip !== existingScan.ip) return false;

    // Must have same ports
    if (newScan.ports.length !== existingScan.ports.length) return false;
    const sortedNew = [...newScan.ports].sort((a, b) => a - b);
    const sortedExisting = [...existingScan.ports].sort((a, b) => a - b);
    if (!sortedNew.every((port, i) => port === sortedExisting[i])) return false;

    // Must be within 5 minutes
    const newTime = new Date(newScan.timestamp).getTime();
    const existingTime = new Date(existingScan.timestamp).getTime();
    const fiveMinutes = 5 * 60 * 1000;

    return (newTime - existingTime) < fiveMinutes;
}

// Remove duplicate scans
function removeDuplicates(scans) {
    const cleaned = [];

    for (let i = scans.length - 1; i >= 0; i--) {
        const current = scans[i];
        let isDupe = false;

        // Check if this is a duplicate of any scan we've already added
        for (const kept of cleaned) {
            if (isDuplicateScan(current, kept)) {
                isDupe = true;
                break;
            }
        }

        if (!isDupe) {
            cleaned.push(current);
        }
    }

    return cleaned.reverse();
}

window.onload = function () {
    console.log('Dashboard ready!');
    detectNetwork();
    refreshData();
};

function refreshData() {
    console.log('Loading scan results...');

    fetch('/api/scans')
        .then(response => response.json())
        .then(data => {
            console.log('Scans loaded:', data.scans?.length || 0);
            scanData = removeDuplicates(data.scans || []);
            updateDashboard();
        })
        .catch(error => {
            console.error('Error loading scans:', error);
        });

    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            alertData = data.alerts || [];
            updateAlerts();
        })
        .catch(error => {
            console.error('Error loading alerts:', error);
        });
}

function updateDashboard() {
    document.getElementById('total-scans').textContent = scanData.length;

    const uniqueIPs = new Set(scanData.map(s => s.ip));
    document.getElementById('unique-hosts').textContent = uniqueIPs.size;

    let totalPorts = 0;
    scanData.forEach(scan => {
        totalPorts += scan.ports.length;
    });
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

    if (alertData.length === 0) {
        alertsList.innerHTML = '<p class="empty-state">No security alerts detected.</p>';
        return;
    }

    const uniqueAlerts = new Set();
    const uniqueAlertData = [];

    alertData.forEach(alert => {
        const key = `${alert.ip}:${alert.port}:${alert.level}:${alert.message}`;
        if (!uniqueAlerts.has(key)) {
            uniqueAlerts.add(key);
            uniqueAlertData.push(alert);
        }
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

    if (target === 'localhost') {
        targetIP = '127.0.0.1';
    }
    else if (target === 'router') {
        targetIP = detectedNetwork.gateway;
    }
    else if (target === 'network') {
        targetIP = detectedNetwork.subnet;
        showNotification('Network scan will take a few minutes...', 'info');
    }
    else {
        targetIP = target;
    }

    triggerScan(targetIP, ports);
}

function customScan() {
    const targetIP = document.getElementById('target-ip').value.trim();
    const portsInput = document.getElementById('target-ports').value.trim();

    if (!targetIP) {
        showNotification('Please enter a target address', 'error');
        return;
    }

    let ports;
    if (portsInput) {
        ports = portsInput.split(',').map(p => parseInt(p.trim())).filter(p => p > 0 && p <= 65535);
        if (ports.length === 0) {
            showNotification('Please enter valid port numbers', 'error');
            return;
        }
    }
    else {
        ports = PORT_PRESETS.common;
    }

    triggerScan(targetIP, ports);
}

function triggerScan(target, ports) {
    console.log('Starting scan:', target);

    const allButtons = document.querySelectorAll('button');
    allButtons.forEach(btn => {
        btn.disabled = true;
        btn.style.opacity = '0.6';
    });

    showNotification(`Scanning ${getFriendlyName(target)}...`, 'info');

    const payload = JSON.stringify({ target: target, ports: ports });

    fetch('/api/scan/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload
    })
        .then(response => response.json())
        .then(data => {
            console.log('Scan finished');
            showNotification('Scan complete!', 'success');
            setTimeout(refreshData, 1500);
        })
        .catch(error => {
            console.error('Scan error:', error);
            showNotification('Scan failed: ' + error.message, 'error');
        })
        .finally(() => {
            setTimeout(() => {
                allButtons.forEach(btn => {
                    btn.disabled = false;
                    btn.style.opacity = '1';
                });
            }, 2000);
        });
}

function clearData() {
    if (!confirm('Are you sure you want to clear all scan history?')) {
        return;
    }

    fetch('/api/clear', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            showNotification('History cleared', 'success');
            scanData = [];
            alertData = [];
            updateDashboard();
            updateAlerts();
        })
        .catch(error => {
            console.error('Clear error:', error);
            showNotification('Failed to clear history', 'error');
        });
}

setInterval(refreshData, 10000);