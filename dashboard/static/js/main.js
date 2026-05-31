/* HostSentinel – main.js */
(function () {
  'use strict';

  // ── SSE live feed ──────────────────────────────────────────────────────
  let es;

  function connectSSE() {
    es = new EventSource('/stream');

    es.onmessage = function (e) {
      const data = JSON.parse(e.data);
      if (data.type === 'heartbeat') return;
      if (data.type === 'event') {
        showToast(data);
        refreshStats();
        refreshEventFeed();
        if (typeof window.refreshPorts === 'function' &&
            (data.event_type === 'NEW_PORT' || data.event_type === 'PORT_CLOSED')) {
          window.refreshPorts();
        }
        if (typeof window.refreshIntegrity === 'function' &&
            data.event_type === 'FILE_MODIFIED') {
          window.refreshIntegrity();
        }
      }
    };

    es.onerror = function () {
      setLiveBadge(false);
      setTimeout(connectSSE, 5000);
    };

    es.onopen = function () {
      setLiveBadge(true);
    };
  }

  function setLiveBadge(live) {
    const el = document.getElementById('live-badge');
    if (!el) return;
    if (live) {
      el.className = 'badge bg-success-subtle text-success-emphasis border border-success-subtle';
      el.innerHTML = '<i class="bi bi-circle-fill" style="font-size:.5rem;vertical-align:middle"></i> LIVE';
    } else {
      el.className = 'badge bg-danger-subtle text-danger-emphasis border border-danger-subtle';
      el.innerHTML = '<i class="bi bi-circle-fill" style="font-size:.5rem;vertical-align:middle"></i> OFFLINE';
    }
  }

  // ── Toast notifications ────────────────────────────────────────────────
  const SEV_BG = {
    CRITICAL: 'bg-danger',
    HIGH:     'bg-warning text-dark',
    MEDIUM:   'bg-info text-dark',
    LOW:      'bg-secondary',
    INFO:     'bg-dark border border-secondary',
  };

  function showToast(evt) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const sev = evt.severity || 'INFO';
    const bg  = SEV_BG[sev] || 'bg-secondary';
    const ts  = new Date().toISOString().slice(11, 19);
    const ip  = evt.source_ip ? `<br><code style="font-size:.75em">${evt.source_ip}</code>` : '';
    const det = (evt.details || '').substring(0, 100);

    const html = `
      <div class="toast ${bg}" role="alert" aria-live="assertive">
        <div class="d-flex">
          <div class="toast-body py-2 px-3">
            <div class="fw-semibold">${evt.event_type.replace(/_/g,' ')}
              <span class="opacity-50 fw-normal" style="font-size:.75em">${ts}</span>
            </div>
            ${ip}
            <div style="font-size:.78em;opacity:.85;margin-top:.2rem">${det}</div>
          </div>
          <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
      </div>`;

    container.insertAdjacentHTML('beforeend', html);
    const el = container.lastElementChild;
    const t  = bootstrap.Toast.getOrCreateInstance(el, { delay: 6000 });
    t.show();
    el.addEventListener('hidden.bs.toast', () => el.remove());
  }

  // ── Periodic stats refresh ─────────────────────────────────────────────
  async function refreshStats() {
    try {
      const data = await fetch('/api/stats').then(r => r.json());
      const map = {
        'stat-events_today':     data.events_today,
        'stat-brute_force_today':data.brute_force_today,
        'stat-honeypot_today':   data.honeypot_today,
        'stat-unique_attackers': data.unique_attackers,
        'stat-total_events':     data.total_events,
        'stat-critical_unacked': data.critical_unacked,
        'stat-file_changes':     data.file_changes,
        'stat-honeypot_total':   data.honeypot_total,
      };
      for (const [id, val] of Object.entries(map)) {
        const el = document.getElementById(id);
        if (el && val !== undefined) el.textContent = val.toLocaleString();
      }
    } catch (e) { /* swallow */ }
  }

  // ── Event feed polling ─────────────────────────────────────────────────
  async function refreshEventFeed() {
    const tbody = document.querySelector('#live-feed-table tbody');
    if (!tbody) return;
    try {
      const data = await fetch('/api/events?limit=15').then(r => r.json());
      if (!data.events || !data.events.length) return;
      tbody.innerHTML = data.events.map(ev => {
        const sev = ev.severity || 'INFO';
        const ts = (ev.timestamp || '').slice(0, 16).replace('T', ' ');
        const ipHtml = ev.source_ip
          ? `<a href="/attacker/${ev.source_ip}" class="font-mono text-info small">${ev.source_ip}</a>`
          : '<span class="text-muted">—</span>';
        return `<tr>
          <td class="text-muted font-mono small">${ts}</td>
          <td>${(ev.event_type || '').replace(/_/g, ' ')}</td>
          <td><span class="badge sev-${sev.toLowerCase()}">${sev}</span></td>
          <td>${ipHtml}</td>
          <td class="small text-truncate" style="max-width:220px">${(ev.details || '—').substring(0, 80)}</td>
        </tr>`;
      }).join('');
    } catch (e) { /* swallow */ }
  }

  // ── Init ───────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    connectSSE();
    setInterval(refreshStats, 10000);
    setInterval(refreshEventFeed, 10000);
  });
})();
