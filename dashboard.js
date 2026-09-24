/* ==========================================================================
   EmailShield - Dashboard & Chart.js Integration
   ========================================================================== */

let threatChartInstance = null;

async function loadDashboardStats() {
  const data = await apiGet('/api/dashboard/stats');
  if (data.error) return;

  // Update Stat Cards
  if (document.getElementById('stat-total')) document.getElementById('stat-total').innerText = data.total_analyzed || 0;
  if (document.getElementById('stat-threats')) document.getElementById('stat-threats').innerText = data.threats_detected || 0;
  if (document.getElementById('stat-high-risk')) document.getElementById('stat-high-risk').innerText = data.high_risk_cases || 0;
  if (document.getElementById('stat-24h')) document.getElementById('stat-24h').innerText = data.last_24h || 0;

  // Render Chart.js Threat Distribution
  const ctx = document.getElementById('threatOverviewChart');
  if (ctx) {
    const chartData = data.threat_breakdown || { safe: 5, suspicious: 2, high_risk: 4, malicious: 3 };
    
    if (threatChartInstance) threatChartInstance.destroy();

    threatChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Safe', 'Suspicious', 'Spoofing / Phishing', 'Malicious / BEC'],
        datasets: [{
          data: [chartData.safe, chartData.suspicious, chartData.high_risk, chartData.malicious],
          backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#7c3aed'],
          borderWidth: 2,
          borderColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { font: { family: 'Inter', size: 12 }, padding: 15 }
          }
        },
        cutout: '70%'
      }
    });
  }

  // Render Recent Investigations Table
  const tbody = document.getElementById('recent-investigations-tbody');
  if (tbody && data.recent_cases) {
    tbody.innerHTML = '';
    data.recent_cases.forEach(c => {
      let badgeClass = 'high';
      if (c.classification === 'SAFE') badgeClass = 'safe';
      else if (c.classification === 'SUSPICIOUS' || c.classification === 'SPOOFING') badgeClass = 'suspicious';

      const row = `
        <tr>
          <td><span class="fw-bold text-primary">${c.case_number}</span></td>
          <td><div class="text-truncate" style="max-width: 250px;">${c.subject}</div></td>
          <td><span class="badge-threat ${badgeClass}">${c.classification}</span></td>
          <td><span class="fw-bold">${c.risk_score} / 100</span></td>
          <td><small class="text-muted">${c.created_at || 'Just now'}</small></td>
          <td>
            <a href="/investigation/${c.case_number}" class="btn btn-sm btn-outline-primary rounded-pill px-3">
              <i class="bi bi-shield-shaded me-1"></i> Investigate
            </a>
          </td>
        </tr>
      `;
      tbody.insertAdjacentHTML('beforeend', row);
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('threatOverviewChart')) {
    loadDashboardStats();
  }
});
