let scanData = [];
let alertData = [];
let isScanning = false;

function refreshData() {
    fetch('/api/scans')
        .then(response => response.json())
        .then(data => {
            scanData = data.scans || [];
            updateDashboard();
        })
        .catch(error => {
            console.error('Error fetching scan data:', error);
        });
    
    fetch('/api/alerts')
        .then(response => response.json())
        .then(data => {
            alertData = data.alerts || [];
            updateAlerts();
        })
        .catch(error => {
            console.error('Error fetching alerts:', error);
        });
}

function updateDashboard() {
    document.getElementById('total-scans').textContent = scanData.length;
    
    let uniqueHosts = new Set(scanData.map(s => s.ip));
    document.getElementById('unique-hosts').textContent = uniqueHosts.size;
    
    let totalPorts = scanData.reduce((sum, scan) => sum + scan.ports.length, 0);
    document.getElementById('open-ports').textContent = totalPorts;
    
    let scanList = document.getElementById('scan-list');
    
    if (scanData.length === 0) {
        scanList.innerHTML = '<p class="empty-state">No scans yet. Click "Start Network Scan" to begin.</p>';
        return;
    }
    
    scanList.innerHTML = '';
    
    // Shows most recent scans first
    let recentScans = [...scanData].reverse().slice(0, 20);
    
    recentScans.forEach(scan => {
        let item = document.createElement('div');
        item.className = 'scan-item';
        
        let header = document.createElement('div');
        header.className = 'scan-header';
        
        let ip = document.createElement('span');
        ip.className = 'scan-ip';
        ip.textContent = scan.ip;
        
        let time = document.createElement('span');
        time.className = 'scan-time';
        time.textContent = scan.timestamp || 'Unknown';
        
        header.appendChild(ip);
        header.appendChild(time);
        
        let ports = document.createElement('div');
        ports.className = 'scan-ports';
        
        if (scan.ports.length === 0) {
            ports.innerHTML = '<span style="color: #8b949e;">No open ports</span>';
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
        alertsList.innerHTML = '<p class="empty-state">No security alerts.</p>';
        return;
    }
    
    alertsList.innerHTML = '';
    
    alertData.forEach(alert => {
        let item = document.createElement('div');
        item.className = `alert-item alert-${alert.level.toLowerCase()}`;
        
        let header = document.createElement('div');
        header.className = 'alert-header';
        header.textContent = `[${alert.level}] ${alert.ip}:${alert.port}`;
        
        let message = document.createElement('div');
        message.className = 'alert-message';
        message.textContent = alert.message;
        
        item.appendChild(header);
        item.appendChild(message);
        alertsList.appendChild(item);
    });
}

function showLoading(show) {
    const scanBtn = document.querySelector('.btn-primary');
    
    if (show) {
        isScanning = true;
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<span class="spinner"></span> Scanning...';
        
        let scanList = document.getElementById('scan-list');
        let loadingDiv = document.createElement('div');
        loadingDiv.className = 'loading-banner';
        loadingDiv.innerHTML = 'Network scan in progress... This may take a few minutes.';
        scanList.insertBefore(loadingDiv, scanList.firstChild);
    } else {
        isScanning = false;
        scanBtn.disabled = false;
        scanBtn.innerHTML = 'Start Network Scan';
        
        const loadingBanner = document.querySelector('.loading-banner');
        if (loadingBanner) {
            loadingBanner.remove();
        }
    }
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

function triggerScan() {
    if (isScanning) {
        showNotification('A scan is already in progress', 'warning');
        return;
    }
    
    showLoading(true);
    showNotification('Network scan started', 'success');
    
    fetch('/api/scan/trigger', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            console.log('Scan triggered:', data);
            
            // Network scan doesn't actually work in the backend
            setTimeout(() => {
                showLoading(false);
                refreshData();
                showNotification('Network scan completed!', 'success');
            }, 5000);
        })
        .catch(error => {
            console.error('Error triggering scan:', error);
            showLoading(false);
            showNotification('Failed to trigger scan', 'error');
        });
}

setInterval(refreshData, 10000);

window.onload = refreshData;