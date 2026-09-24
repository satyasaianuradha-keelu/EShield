/* ==========================================================================
   EmailShield - Live Email Monitor Simulator
   ========================================================================== */

let monitorInterval = null;
let isMonitoring = false;

function toggleMonitoring() {
  const btn = document.getElementById('btn-toggle-monitor');
  const statusBadge = document.getElementById('monitor-status-badge');
  
  if (isMonitoring) {
    // Turn Off
    isMonitoring = false;
    if (monitorInterval) clearInterval(monitorInterval);
    if (btn) {
      btn.className = 'btn btn-outline-success rounded-pill px-4';
      btn.innerHTML = '<i class="bi bi-play-circle-fill me-1"></i> Start Live Monitoring';
    }
    if (statusBadge) {
      statusBadge.className = 'badge bg-secondary px-3 py-2 fs-6';
      statusBadge.innerText = 'Monitoring: OFF';
    }
    showToast("Email Monitoring Paused", "Simulated inbox monitoring has been stopped.", "info");
  } else {
    // Turn On
    isMonitoring = true;
    if (btn) {
      btn.className = 'btn btn-danger rounded-pill px-4';
      btn.innerHTML = '<i class="bi bi-pause-circle-fill me-1"></i> Pause Monitoring';
    }
    if (statusBadge) {
      statusBadge.className = 'badge bg-success px-3 py-2 fs-6';
      statusBadge.innerText = 'Monitoring: ACTIVE';
    }
    showToast("Email Monitoring Active", "System listening for incoming emails in real-time.", "success");
    
    // Trigger immediate sample incoming email
    triggerSimulatedEmail();
    
    // Schedule periodic triggers
    monitorInterval = setInterval(triggerSimulatedEmail, 12000);
  }
}

async function triggerSimulatedEmail() {
  if (!isMonitoring) return;
  
  const res = await apiPost('/api/monitor/trigger', {});
  if (res.error) return;

  // Append new email row to monitor feed table
  const tbody = document.getElementById('monitor-feed-tbody');
  if (tbody) {
    let badgeClass = 'high';
    if (res.classification === 'SAFE') badgeClass = 'safe';
    else if (res.classification === 'SUSPICIOUS' || res.classification === 'SPOOFING') badgeClass = 'suspicious';

    const newRow = `
      <tr class="table-warning border-start border-danger border-4">
        <td><span class="badge bg-dark">${res.case_number}</span></td>
        <td><strong class="text-dark">${res.subject}</strong></td>
        <td><small class="text-muted">${res.sender}</small></td>
        <td><span class="badge-threat ${badgeClass}">${res.classification}</span></td>
        <td><span class="fw-bold">${res.risk_score} / 100</span></td>
        <td><small class="text-muted">Just now</small></td>
        <td>
          <a href="/investigation/${res.case_number}" class="btn btn-sm btn-primary rounded-pill">
            <i class="bi bi-search me-1"></i> View Details
          </a>
        </td>
      </tr>
    `;
    tbody.insertAdjacentHTML('afterbegin', newRow);
  }

  // Show security alert toast
  if (res.risk_score >= 50) {
    showToast(
      `🚨 Security Alert: ${res.classification}`,
      `High risk email detected from ${res.sender}. Case: ${res.case_number}`,
      res.risk_score >= 75 ? 'danger' : 'warning'
    );
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const btnToggle = document.getElementById('btn-toggle-monitor');
  if (btnToggle) {
    btnToggle.addEventListener('click', toggleMonitoring);
  }
  
  const btnManualTrigger = document.getElementById('btn-manual-trigger');
  if (btnManualTrigger) {
    btnManualTrigger.addEventListener('click', () => {
      triggerSimulatedEmail();
      showToast("Simulated Email Arrived", "Inbound email processed and evaluated.", "info");
    });
  }
});
