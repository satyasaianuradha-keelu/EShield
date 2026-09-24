/* ==========================================================================
   EmailShield - Global Application Controller & Utilities
   ========================================================================== */

function showToast(title, message, type = 'info') {
  const toastContainer = document.getElementById('toast-container');
  if (!toastContainer) return;

  const toastId = 'toast-' + Date.now();
  let bgClass = 'bg-primary text-white';
  let icon = 'bi-info-circle-fill';

  if (type === 'danger' || type === 'high') {
    bgClass = 'bg-danger text-white';
    icon = 'bi-exclamation-triangle-fill';
  } else if (type === 'warning' || type === 'medium') {
    bgClass = 'bg-warning text-dark';
    icon = 'bi-exclamation-diamond-fill';
  } else if (type === 'success' || type === 'safe') {
    bgClass = 'bg-success text-white';
    icon = 'bi-check-circle-fill';
  }

  const toastHtml = `
    <div id="${toastId}" class="toast align-items-center ${bgClass} border-0 show shadow-lg mb-2" role="alert" aria-live="assertive" aria-atomic="true">
      <div class="d-flex">
        <div class="toast-body d-flex align-items-center gap-2">
          <i class="bi ${icon} fs-5"></i>
          <div>
            <strong>${title}</strong><br/>
            <small>${message}</small>
          </div>
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    </div>
  `;

  toastContainer.insertAdjacentHTML('beforeend', toastHtml);

  setTimeout(() => {
    const el = document.getElementById(toastId);
    if (el) el.remove();
  }, 5000);
}

// Global API Helper
async function apiPost(url, bodyData) {
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(bodyData)
    });
    return await resp.json();
  } catch (err) {
    console.error("API Error:", err);
    showToast("Server Connection Error", "Unable to communicate with EmailShield backend service.", "danger");
    return { error: err.message };
  }
}

async function apiGet(url) {
  try {
    const resp = await fetch(url);
    return await resp.json();
  } catch (err) {
    console.error("API Error:", err);
    return { error: err.message };
  }
}

// Global Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  // Bind Language Buttons
  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const lang = e.target.getAttribute('data-lang');
      setLanguage(lang);
    });
  });
});
