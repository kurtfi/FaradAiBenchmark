/**
 * Faraday Laya Guard — Dashboard Frontend Logic
 * WebSocket real-time progress + REST API integration
 */

// ─── State ──────────────────────────────────────────────────────────────────

const state = {
    ws: null,
    currentPage: 'dashboard',
    activeRunId: null,
    datasets: [],
    models: [],
    runs: [],
    reconnectAttempts: 0,
    maxReconnect: 10,
};

// ─── DOM Helpers ────────────────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ─── WebSocket ──────────────────────────────────────────────────────────────

function connectWS() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    state.ws = new WebSocket(`${protocol}//${location.host}/ws`);

    state.ws.onopen = () => {
        state.reconnectAttempts = 0;
        updateConnectionBadge(true);
        console.log('[WS] Connected');
    };

    state.ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleWSMessage(msg);
    };

    state.ws.onclose = () => {
        updateConnectionBadge(false);
        if (state.reconnectAttempts < state.maxReconnect) {
            state.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, state.reconnectAttempts), 15000);
            setTimeout(connectWS, delay);
        }
    };

    state.ws.onerror = () => {
        state.ws.close();
    };
}

function updateConnectionBadge(connected) {
    const dot = $('#connection-dot');
    const text = $('#connection-text');
    if (dot) {
        dot.classList.toggle('connected', connected);
    }
    if (text) {
        text.textContent = connected ? 'Live' : 'Disconnected';
    }
}

// ─── WebSocket Message Handler ──────────────────────────────────────────────

function handleWSMessage(msg) {
    switch (msg.type) {
        case 'progress':
            updateProgress(msg);
            break;
        case 'run_started':
            showToast(`Benchmark başlatıldı: ${msg.total_cases} test`, 'info');
            break;
        case 'run_completed':
            handleRunCompleted(msg);
            break;
        case 'error':
            showToast(`Hata: ${msg.message}`, 'error');
            resetProgress();
            break;
        case 'pong':
            break;
    }
}

// ─── Progress Updates ───────────────────────────────────────────────────────

function updateProgress(data) {
    // Show progress section, hide idle
    const idle = $('#idle-state');
    const progress = $('#progress-section');
    if (idle) idle.style.display = 'none';
    if (progress) progress.style.display = 'flex';

    // Update ring
    const pct = data.pct || 0;
    const ring = $('#progress-ring-fill');
    if (ring) {
        const circumference = 2 * Math.PI * 90; // r=90
        const offset = circumference - (pct / 100) * circumference;
        ring.style.strokeDashoffset = offset;
    }

    // Update text
    setText('#progress-pct', `${Math.round(pct)}%`);
    setText('#progress-evaluated', `${data.evaluated}/${data.total}`);
    setText('#progress-throughput', `${data.throughput}`);
    setText('#progress-elapsed', `${data.elapsed_secs}s`);

    // Update live metrics
    updateMetric('accuracy', data.accuracy, '%');
    updateMetric('precision', data.precision, '%');
    updateMetric('recall', data.recall, '%');
    updateMetric('f1', data.f1, '%');

    // Update confusion matrix
    setText('#cm-tp', data.tp);
    setText('#cm-tn', data.tn);
    setText('#cm-fp', data.fp);
    setText('#cm-fn', data.fn);
}

function updateMetric(id, value, suffix) {
    const el = $(`#metric-${id}`);
    if (!el) return;
    el.textContent = `${value}${suffix}`;

    // Color coding
    el.className = 'metric-value';
    if (suffix === '%') {
        if (value >= 85) el.classList.add('good');
        else if (value >= 60) el.classList.add('warn');
        else el.classList.add('bad');
    }
}

function handleRunCompleted(data) {
    showToast(`✅ Benchmark tamamlandı! F1: ${data.f1}% — ${data.duration_secs}s`, 'success');

    // Update final metrics
    updateMetric('accuracy', data.accuracy, '%');
    updateMetric('precision', data.precision, '%');
    updateMetric('recall', data.recall, '%');
    updateMetric('f1', data.f1, '%');
    updateMetric('fpr', data.fpr, '%');
    updateMetric('latency', data.avg_latency_ms, 'ms');

    // Show button to view results
    const actions = $('#progress-complete-actions');
    const viewBtn = $('#btn-view-last-run');
    if (actions && viewBtn) {
        actions.style.display = 'block';
        viewBtn.onclick = () => viewRunDetail(data.run_id);
    }

    // Re-enable start button
    const btn = $('#btn-start');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = '🚀 Start Benchmark';
    }

    state.activeRunId = null;

    // Refresh history
    loadRuns();
}

function resetProgress() {
    const idle = $('#idle-state');
    const progress = $('#progress-section');
    if (idle) idle.style.display = 'flex';
    if (progress) progress.style.display = 'none';

    const actions = $('#progress-complete-actions');
    if (actions) actions.style.display = 'none';

    const btn = $('#btn-start');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = '🚀 Start Benchmark';
    }
    state.activeRunId = null;
}

// ─── API Calls ──────────────────────────────────────────────────────────────

async function loadDatasets() {
    try {
        const res = await fetch('/api/datasets');
        state.datasets = await res.json();
        renderDatasetSelect();
    } catch (e) {
        console.error('Failed to load datasets:', e);
    }
}

async function loadModels() {
    try {
        const res = await fetch('/api/models');
        state.models = await res.json();
        renderModelSelect();
    } catch (e) {
        console.error('Failed to load models:', e);
    }
}

async function loadRuns() {
    try {
        const res = await fetch('/api/runs');
        state.runs = await res.json();
        renderRunsTable();
    } catch (e) {
        console.error('Failed to load runs:', e);
    }
}

async function startBenchmark() {
    const datasetSelect = $('#dataset-select');
    const modelSelect = $('#model-select');

    if (!datasetSelect.value || !modelSelect.value) {
        showToast('Dataset ve model seçiniz', 'error');
        return;
    }

    const dataset = state.datasets.find(d => d.id === datasetSelect.value);
    if (!dataset) return;

    const btn = $('#btn-start');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner">⏳</span> Çalışıyor...';

    const actions = $('#progress-complete-actions');
    if (actions) actions.style.display = 'none';

    // Reset progress display
    updateProgress({
        pct: 0, evaluated: 0, total: 0,
        throughput: 0, elapsed_secs: 0,
        accuracy: 0, precision: 0, recall: 0, f1: 0,
    });
    setText('#cm-tp', 0);
    setText('#cm-tn', 0);
    setText('#cm-fp', 0);
    setText('#cm-fn', 0);

    try {
        const res = await fetch('/api/runs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                dataset_path: dataset.path,
                dataset_name: dataset.id,
                model_name: modelSelect.value,
            })
        });
        const data = await res.json();

        if (data.error) {
            showToast(`Hata: ${data.error}`, 'error');
            btn.disabled = false;
            btn.innerHTML = '🚀 Start Benchmark';
            return;
        }

        state.activeRunId = data.run_id;
        showToast(`Run başlatıldı: ${data.run_id}`, 'info');
    } catch (e) {
        showToast(`Bağlantı hatası: ${e.message}`, 'error');
        btn.disabled = false;
        btn.innerHTML = '🚀 Start Benchmark';
    }
}

async function viewRunDetail(runId) {
    try {
        const res = await fetch(`/api/runs/${runId}`);
        const data = await res.json();
        if (data.error) {
            showToast(data.error, 'error');
            return;
        }
        renderRunDetailModal(data);
    } catch (e) {
        showToast(`Detay yüklenemedi: ${e.message}`, 'error');
    }
}

async function deleteRun(runId, event) {
    event.stopPropagation();
    if (!confirm(`"${runId}" kaydını silmek istediğinizden emin misiniz?`)) return;

    try {
        await fetch(`/api/runs/${runId}`, { method: 'DELETE' });
        showToast(`${runId} silindi`, 'info');
        loadRuns();
    } catch (e) {
        showToast(`Silinemedi: ${e.message}`, 'error');
    }
}

// ─── Renderers ──────────────────────────────────────────────────────────────

function renderDatasetSelect() {
    const select = $('#dataset-select');
    if (!select) return;
    select.innerHTML = '<option value="">Dataset seçin...</option>';
    state.datasets.forEach(ds => {
        const opt = document.createElement('option');
        opt.value = ds.id;
        opt.textContent = `${ds.name} (${ds.rows.toLocaleString()} rows, ${ds.size_kb} KB)`;
        select.appendChild(opt);
    });
}

function renderModelSelect() {
    const select = $('#model-select');
    if (!select) return;
    select.innerHTML = '';
    state.models.forEach(m => {
        const opt = document.createElement('option');
        opt.value = m.id;
        opt.textContent = `${m.icon} ${m.name}`;
        if (m.status === 'unavailable') {
            opt.textContent += ' (N/A)';
            opt.disabled = true;
        }
        select.appendChild(opt);
    });
}

function renderRunsTable() {
    const tbody = $('#runs-tbody');
    const historyTbody = $('#history-tbody');

    [tbody, historyTbody].forEach(el => {
        if (!el) return;
        if (state.runs.length === 0) {
            el.innerHTML = `
                <tr><td colspan="9" style="text-align:center; padding: 40px; color: var(--text-tertiary);">
                    Henüz benchmark çalıştırılmamış
                </td></tr>`;
            return;
        }

        el.innerHTML = state.runs.map(r => {
            const statusBadge = getStatusBadge(r.status);
            const startedAt = r.started_at ? new Date(r.started_at).toLocaleString('tr-TR') : '—';
            return `
                <tr onclick="viewRunDetail('${r.run_id}')">
                    <td><span class="mono text-sm">${r.run_id}</span></td>
                    <td>${r.dataset_name}</td>
                    <td>${r.model_name}</td>
                    <td class="mono">${r.total_cases || '—'}</td>
                    <td class="mono ${getMetricClass(r.accuracy)}">${r.accuracy ? r.accuracy + '%' : '—'}</td>
                    <td class="mono ${getMetricClass(r.f1)}">${r.f1 ? r.f1 + '%' : '—'}</td>
                    <td class="mono">${r.avg_latency_ms ? r.avg_latency_ms + 'ms' : '—'}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <span class="text-sm text-muted">${startedAt}</span>
                        <button class="btn btn-danger btn-sm" onclick="deleteRun('${r.run_id}', event)" title="Sil" style="margin-left:8px;">✕</button>
                    </td>
                </tr>`;
        }).join('');
    });
}

function getStatusBadge(status) {
    const map = {
        completed: '<span class="badge badge-completed">✓ Completed</span>',
        running: '<span class="badge badge-running">⟳ Running</span>',
        error: '<span class="badge badge-error">✕ Error</span>',
        pending: '<span class="badge badge-pending">◌ Pending</span>',
    };
    return map[status] || `<span class="badge badge-pending">${status}</span>`;
}

function getMetricClass(value) {
    if (!value) return '';
    if (value >= 85) return 'case-correct';
    if (value >= 60) return '';
    return 'case-incorrect';
}

function renderRunDetailModal(data) {
    const modal = $('#run-detail-modal');
    if (!modal) return;

    // Header info
    setText('#modal-run-id', data.run_id);
    setText('#modal-dataset', `${data.dataset_name} · ${data.model_name}`);
    setText('#modal-status', data.status);

    // Metrics
    const metricsHtml = [
        { label: 'Accuracy', value: data.accuracy, suffix: '%' },
        { label: 'Precision', value: data.precision, suffix: '%' },
        { label: 'Recall', value: data.recall, suffix: '%' },
        { label: 'F1 Score', value: data.f1, suffix: '%' },
        { label: 'FPR', value: data.fpr, suffix: '%' },
        { label: 'Avg Latency', value: data.avg_latency_ms, suffix: 'ms' },
        { label: 'P95 Latency', value: data.p95_latency_ms, suffix: 'ms' },
        { label: 'Duration', value: data.duration_secs, suffix: 's' },
    ].map(m => {
        const cls = m.suffix === '%' ? (m.value >= 85 ? 'good' : m.value >= 60 ? 'warn' : 'bad') : 'info';
        return `<div class="metric-card">
            <div class="metric-label">${m.label}</div>
            <div class="metric-value ${cls}">${m.value ?? '—'}<span class="metric-suffix">${m.suffix}</span></div>
        </div>`;
    }).join('');
    $('#modal-metrics').innerHTML = metricsHtml;

    // Confusion matrix
    setText('#modal-tp', data.tp);
    setText('#modal-tn', data.tn);
    setText('#modal-fp', data.fp);
    setText('#modal-fn', data.fn);

    // Category breakdown
    const catContainer = $('#modal-categories');
    if (catContainer && data.category_stats) {
        const cats = Object.entries(data.category_stats);
        catContainer.innerHTML = cats.map(([name, stats]) => {
            const pct = stats.total > 0 ? Math.round((stats.correct / stats.total) * 100) : 0;
            const cls = pct >= 80 ? 'high' : pct >= 50 ? 'mid' : 'low';
            return `
                <div class="category-bar">
                    <span class="category-name">${name}</span>
                    <div class="category-fill-container">
                        <div class="category-fill ${cls}" style="width: ${pct}%"></div>
                    </div>
                    <span class="category-pct ${cls === 'high' ? 'case-correct' : cls === 'low' ? 'case-incorrect' : ''}">${pct}%</span>
                </div>`;
        }).join('');
    }

    // Case results — store for detail popup and filtering
    state.currentRunCases = data.case_results || [];
    state.caseFilter = 'all';
    state.caseSearch = '';

    const searchInput = $('#case-search-input');
    if (searchInput) searchInput.value = '';
    $$('.case-filter-chip').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === 'all');
    });

    const casesSection = $('#modal-cases-section');
    if (casesSection) {
        if (state.currentRunCases.length > 0) {
            casesSection.style.display = 'block';
            renderFilteredCases();
        } else {
            casesSection.style.display = 'none';
        }
    }

    modal.classList.add('open');
}

function renderFilteredCases() {
    const cases = state.currentRunCases || [];
    const search = (state.caseSearch || '').toLowerCase().trim();
    const filter = state.caseFilter || 'all';

    // Calculate filter counts
    const counts = {
        all: cases.length,
        mismatch: cases.filter(c => !c.correct).length,
        fp: cases.filter(c => !c.is_malicious && c.predicted_blocked).length,
        fn: cases.filter(c => c.is_malicious && !c.predicted_blocked).length,
        correct: cases.filter(c => c.correct).length,
    };

    setText('#count-all', counts.all);
    setText('#count-mismatch', counts.mismatch);
    setText('#count-fp', counts.fp);
    setText('#count-fn', counts.fn);
    setText('#count-correct', counts.correct);

    // Apply filtering
    const filtered = [];
    cases.forEach((c, idx) => {
        if (filter === 'mismatch' && c.correct) return;
        if (filter === 'fp' && (c.is_malicious || !c.predicted_blocked)) return;
        if (filter === 'fn' && (!c.is_malicious || c.predicted_blocked)) return;
        if (filter === 'correct' && !c.correct) return;

        if (search) {
            const haystack = `${c.id} ${c.domain} ${c.tool_name} ${c.cwe || ''} ${c.source || ''} ${c.context || ''} ${c.tool_arguments || ''}`.toLowerCase();
            if (!haystack.includes(search)) return;
        }

        filtered.push({ ...c, _originalIdx: idx });
    });

    const caseTbody = $('#modal-cases-tbody');
    if (!caseTbody) return;

    if (filtered.length === 0) {
        caseTbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="padding: var(--space-6); text-align: center; color: var(--text-tertiary);">Kriterlere uygun test case bulunamadı.</td></tr>`;
        return;
    }

    caseTbody.innerHTML = filtered.map(c => `
        <tr class="case-row" onclick="showCaseDetail(${c._originalIdx})" title="Tıkla: payload detayını gör">
            <td class="case-result-icon ${c.correct ? 'case-correct' : 'case-incorrect'}">${c.correct ? '✓' : '✕'}</td>
            <td class="mono font-semibold">${c.id}</td>
            <td><span class="badge-domain">${c.domain}</span></td>
            <td class="mono text-sm">${c.tool_name}</td>
            <td>${c.is_malicious ? '🔴 Zararlı' : '🟢 Meşru'}</td>
            <td>${c.predicted_blocked ? '🛑 Blocked' : '✅ Allowed'}</td>
            <td class="mono">${c.latency_ms}ms</td>
            <td class="case-expand-icon">▸</td>
        </tr>
    `).join('');
}

function filterCasesBy(filterType) {
    state.caseFilter = filterType;
    $$('.case-filter-chip').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filterType);
    });
    renderFilteredCases();
}

function handleCaseSearch(val) {
    state.caseSearch = val;
    renderFilteredCases();
}

function copyPayload(btn) {
    const codeEl = btn.closest('.case-detail-section').querySelector('code');
    if (!codeEl) return;
    const text = codeEl.innerText;
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '✅ Kopyalandı!';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.innerHTML = orig;
            btn.classList.remove('copied');
        }, 1500);
    }).catch(err => {
        console.error('Copy failed:', err);
    });
}

function showCaseDetail(idx) {
    const c = state.currentRunCases[idx];
    if (!c) return;

    const detail = $('#case-detail-drawer');
    if (!detail) return;

    // Populate detail drawer
    const correctClass = c.correct ? 'case-correct' : 'case-incorrect';
    const verdictIcon = c.correct ? '✅' : '❌';

    detail.innerHTML = `
        <div class="case-detail-header">
            <div class="case-detail-title">
                <span class="case-result-icon ${correctClass}" style="font-size: 1.2rem;">${c.correct ? '✓' : '✕'}</span>
                <span>${c.id}</span>
            </div>
            <button class="modal-close" onclick="closeCaseDetail()">✕</button>
        </div>

        <div class="case-detail-meta">
            <div class="case-meta-chip">
                <span class="case-meta-label">Source</span>
                <span class="case-meta-value">${c.source || '—'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Domain</span>
                <span class="case-meta-value">${c.domain}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Tier</span>
                <span class="case-meta-value mono" style="color: #6366f1; font-weight: 600;">${c.analysis_tier || 'STATIC_CAPABLE'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">CWE</span>
                <span class="case-meta-value">${c.cwe || '—'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Tool</span>
                <span class="case-meta-value mono">${c.tool_name}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Latency</span>
                <span class="case-meta-value mono">${c.latency_ms}ms</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Confidence</span>
                <span class="case-meta-value mono">${(c.confidence * 100).toFixed(1)}%</span>
            </div>
        </div>

        <div class="case-detail-verdict">
            <div class="verdict-box ${c.is_malicious ? 'verdict-malicious' : 'verdict-benign'}">
                <span class="verdict-label">Expected</span>
                <span class="verdict-value">${c.is_malicious ? '🔴 Zararlı (Block)' : '🟢 Meşru (Allow)'}</span>
            </div>
            <div class="verdict-arrow">${c.correct ? '✅' : '❌'}</div>
            <div class="verdict-box ${c.predicted_blocked ? 'verdict-blocked' : 'verdict-allowed'}">
                <span class="verdict-label">Predicted</span>
                <span class="verdict-value">${c.predicted_blocked ? '🛑 Blocked' : '✅ Allowed'}</span>
            </div>
        </div>

        ${c.context ? `
        <div class="case-detail-section">
            <div class="case-section-title">📋 Context</div>
            <div class="case-context-box">${escapeHtml(c.context)}</div>
        </div>` : ''}

        <div class="case-detail-section">
            <div class="flex items-center justify-between" style="margin-bottom: var(--space-2);">
                <div class="case-section-title" style="margin-bottom: 0;">📦 Tool Arguments (Payload)</div>
                <button class="copy-payload-btn" onclick="copyPayload(this)" title="Payload'ı panoya kopyala">📋 Kopyala</button>
            </div>
            <pre class="case-payload-box"><code>${syntaxHighlight(c.tool_arguments || '{}')}</code></pre>
        </div>
    `;

    detail.classList.add('open');
}

function closeCaseDetail() {
    const detail = $('#case-detail-drawer');
    if (detail) detail.classList.remove('open');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function syntaxHighlight(jsonStr) {
    // Simple JSON syntax highlighter
    const escaped = escapeHtml(jsonStr);
    return escaped
        .replace(/"([^"]+)":/g, '<span class="json-key">"$1"</span>:')
        .replace(/: "([^"]*)"/g, ': <span class="json-string">"$1"</span>')
        .replace(/: (\d+\.?\d*)/g, ': <span class="json-number">$1</span>')
        .replace(/: (true|false)/g, ': <span class="json-bool">$1</span>')
        .replace(/: (null)/g, ': <span class="json-null">$1</span>');
}

function closeModal() {
    const modal = $('#run-detail-modal');
    if (modal) modal.classList.remove('open');
}

// ─── Navigation ─────────────────────────────────────────────────────────────

function switchPage(page) {
    state.currentPage = page;
    $$('.page').forEach(el => el.classList.remove('active'));
    $$('.nav-btn').forEach(el => el.classList.remove('active'));

    const pageEl = $(`#page-${page}`);
    if (pageEl) pageEl.classList.add('active');

    const navBtn = $(`.nav-btn[data-page="${page}"]`);
    if (navBtn) navBtn.classList.add('active');

    if (page === 'history') {
        loadRuns();
    }
}

// ─── Toast Notifications ────────────────────────────────────────────────────

function showToast(message, type = 'info') {
    const container = $('#toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(30px)';
        toast.style.transition = '300ms ease';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ─── Utilities ──────────────────────────────────────────────────────────────

function setText(selector, text) {
    const el = $(selector);
    if (el) el.textContent = text;
}

// ─── Initialize ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Load data
    loadDatasets();
    loadModels();
    loadRuns();

    // Connect WebSocket
    connectWS();

    // Navigation
    $$('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => switchPage(btn.dataset.page));
    });

    // Start benchmark button
    const startBtn = $('#btn-start');
    if (startBtn) {
        startBtn.addEventListener('click', startBenchmark);
    }

    // Modal close
    const modalOverlay = $('#run-detail-modal');
    if (modalOverlay) {
        modalOverlay.addEventListener('click', (e) => {
            if (e.target === modalOverlay) closeModal();
        });
    }

    // Dataset select hint update
    const datasetSelect = $('#dataset-select');
    if (datasetSelect) {
        datasetSelect.addEventListener('change', () => {
            const ds = state.datasets.find(d => d.id === datasetSelect.value);
            const hint = $('#dataset-hint');
            if (hint && ds) {
                hint.textContent = `${ds.rows.toLocaleString()} satır · ${ds.size_kb} KB · ${ds.filename}`;
            } else if (hint) {
                hint.textContent = '';
            }
        });
    }

    // WebSocket keepalive
    setInterval(() => {
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify({ type: 'ping' }));
        }
    }, 30000);
});
