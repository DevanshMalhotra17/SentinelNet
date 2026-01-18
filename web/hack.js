let targets = [];
let currentTarget = null;
const COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080];

const VULN_DATABASE = {
    "SSH": {
        "vulnerabilities": [
            { "id": "CVE-2023-38408", "severity": "CRITICAL", "message": "Potential RCE in SSH agent forwarding." },
            { "id": "CVE-2016-2183", "severity": "MEDIUM", "message": "Sweet32 Birthday attack (64-bit block ciphers)." }
        ],
        "recommendation": "Use key-based authentication and disable password login."
    },
    "HTTP": {
        "vulnerabilities": [
            { "id": "CVE-2021-41773", "severity": "CRITICAL", "message": "Path traversal and RCE." }
        ],
        "recommendation": "Implement a Web Application Firewall and keep servers updated."
    },
    "FTP": {
        "vulnerabilities": [
            { "id": "CVE-DEFAULT-PASS", "severity": "MEDIUM", "message": "Anonymous login may be enabled." }
        ],
        "recommendation": "Disable anonymous login and use SFTP instead."
    }
};

window.onload = function () {
    refreshTargets();
};

function log(message, type = 'info') {
    const terminal = document.getElementById('terminal');
    const line = document.createElement('div');
    line.className = 'terminal-line';

    const prompt = document.createElement('span');
    prompt.className = 'prompt';
    prompt.textContent = 'guest@sentinelnet:~$';

    const content = document.createElement('span');
    content.textContent = ` [${new Date().toLocaleTimeString()}] ${message}`;
    if (type === 'error') content.style.color = '#ff3e3e';
    if (type === 'success') content.style.color = '#00ff41';

    line.appendChild(prompt);
    line.appendChild(content);
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function refreshTargets() {
    log("Running network discovery scan (ARP pass)...");
    fetch('/api/discover')
        .then(res => res.json())
        .then(data => {
            targets = data.hosts || [];
            updateTargetList();
            log(`Discovery complete. Found ${targets.length} potential targets.`, 'success');
        })
        .catch(err => {
            log("Discovery failed: " + err.message, 'error');
        });
}

function updateTargetList() {
    const list = document.getElementById('target-list');
    list.innerHTML = '';

    if (targets.length === 0) {
        list.innerHTML = '<li class="empty-state">No live hosts found.</li>';
        return;
    }

    targets.forEach(ip => {
        const item = document.createElement('li');
        item.className = 'target-item';
        item.textContent = ip;
        item.onclick = () => selectTarget(ip, item);
        list.appendChild(item);
    });
}

function selectTarget(ip, element) {
    currentTarget = ip;
    document.querySelectorAll('.target-item').forEach(el => el.classList.remove('active'));
    element.classList.add('active');

    document.getElementById('target-details').style.display = 'block';
    document.getElementById('current-target-ip').textContent = `TARGET: ${ip}`;

    log(`Tactical focus shifted to target: ${ip}`);
}

async function startAudit() {
    if (!currentTarget) return;

    const overlay = document.getElementById('scan-overlay');
    const fill = document.getElementById('progress-fill');
    const subtext = document.getElementById('overlay-subtext');

    overlay.style.display = 'flex';
    log(`Starting deep audit on ${currentTarget}...`);

    let findings = [];

    for (let i = 0; i < COMMON_PORTS.length; i++) {
        const port = COMMON_PORTS[i];
        const progress = ((i + 1) / COMMON_PORTS.length) * 100;

        fill.style.width = `${progress}%`;
        subtext.textContent = `PROBING PORT ${port}...`;

        try {
            const res = await fetch('/api/audit/fingerprint', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: currentTarget, port: port })
            });

            const data = await res.json();
            if (data.banner) {
                log(`Port ${port} active. Banner identified: ${data.banner.substring(0, 50)}...`, 'success');
                findings.push(data);
            }
        } catch (err) {
            //Ignore
        }
    }

    overlay.style.display = 'none';
    generateExposureReport(findings);
}

function generateExposureReport(findings) {
    const report = document.getElementById('exposure-report');
    report.innerHTML = '';

    if (findings.length === 0) {
        report.innerHTML = '<p style="color: #666;">No services identified during audit.</p>';
        log("Audit complete. No external exposure points found.");
        return;
    }

    findings.forEach(f => {
        const card = document.createElement('div');
        card.style.background = 'rgba(255,255,255,0.03)';
        card.style.padding = '1rem';
        card.style.marginBottom = '1rem';
        card.style.borderRadius = '4px';
        card.style.borderLeft = '4px solid ' + (VULN_DATABASE[f.service] ? '#ffaa00' : '#888');

        let html = `<h4 style="color: var(--accent-green); margin: 0;">Port ${f.port} | ${f.service}</h4>`;
        html += `<p style="font-size: 0.8rem; color: #aaa; margin: 5px 0;">Banner: <code>${f.banner}</code></p>`;

        if (VULN_DATABASE[f.service]) {
            const vData = VULN_DATABASE[f.service];
            html += `<p style="font-weight: bold; margin-top: 10px;">POTENTIAL EXPLOITS:</p>`;
            vData.vulnerabilities.forEach(v => {
                const sClass = v.severity === 'CRITICAL' ? 'vuln-critical' : 'vuln-medium';
                html += `<div><span class="vuln-badge ${sClass}">${v.severity}</span> ${v.id}: ${v.message}</div>`;
            });
            html += `<p style="margin-top: 10px; font-size: 0.9rem;">RECOMENDATION: ${vData.recommendation}</p>`;
        } else {
            html += `<p style="font-style: italic; font-size: 0.8rem; margin-top: 5px;">No known CVEs in local lab database for this version string.</p>`;
        }

        card.innerHTML = html;
        report.appendChild(card);
    });

    log(`Audit report generated. ${findings.length} service(s) analyzed.`, 'success');
}
