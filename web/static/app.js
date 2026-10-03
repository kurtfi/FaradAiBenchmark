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
    testCases: {
        page: 1,
        limit: 50,
        dataset: 'all',
        threat_domain: 'all',
        tier: 'all',
        status: 'all',
        search: '',
        sortBy: 'id',
        sortOrder: 'asc',
        searchDebounceTimer: null,
        total: 0,
        totalPages: 1,
        cases: [],
        filtersLoaded: false,
        eventsBound: false,
        activeCaseId: null,
        activeCasePayload: null,
    },
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

    // Read tier scope (all, static, semantic)
    const tierInput = document.querySelector('input[name="tier_scope"]:checked');
    const tierFilter = tierInput ? tierInput.value : 'all';

    // Read L1 toggle (true / false)
    const l1Input = document.querySelector('input[name="enable_l1"]:checked');
    const enableL1 = l1Input ? (l1Input.value === 'true') : true;

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
                dataset_name: dataset.name || dataset.id,
                tier_filter: tierFilter,
                model_name: modelSelect.value,
                enable_l1: enableL1,
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

function updateTierCounts(ds) {
    if (!ds) {
        setText('#tier-count-all', '—');
        setText('#tier-count-static', '—');
        setText('#tier-count-semantic', '—');
        return;
    }
    setText('#tier-count-all', (ds.rows || 0).toLocaleString());
    setText('#tier-count-static', (ds.static_rows || 0).toLocaleString());
    setText('#tier-count-semantic', (ds.semantic_rows || 0).toLocaleString());
    updateTierDescription();
}

function updateTierDescription() {
    const tierInput = document.querySelector('input[name="tier_scope"]:checked');
    const tier = tierInput ? tierInput.value : 'all';
    const datasetSelect = $('#dataset-select');
    const ds = state.datasets.find(d => d.id === (datasetSelect ? datasetSelect.value : ''));

    const descEl = $('#tier-scope-desc');
    if (!descEl) return;

    if (tier === 'static') {
        const cnt = ds ? (ds.static_rows || 0).toLocaleString() : '811';
        descEl.textContent = `⚡ Statik Kapsam: Yalnızca mikrosaniyelik regex/DLP ile tespit edilebilir kurallar (${cnt} vaka - STATIC_CAPABLE).`;
    } else if (tier === 'semantic') {
        const cnt = ds ? (ds.semantic_rows || 0).toLocaleString() : '1,189';
        descEl.textContent = `🧠 Semantik Kapsam: L2 derin anlamsal analiz gerektiren karmaşık senaryolar (${cnt} vaka - SEMANTIC_REQUIRED).`;
    } else {
        const cnt = ds ? (ds.rows || 0).toLocaleString() : '2,000';
        descEl.textContent = `🌐 Tümü: Statik kural ve semantik test vakalarının tamamı (${cnt} vaka).`;
    }
}

function onTierRadioChanged() {
    const tierInputs = document.querySelectorAll('input[name="tier_scope"]');
    tierInputs.forEach(input => {
        const label = input.closest('.tier-radio-btn');
        if (label) {
            label.classList.toggle('active', input.checked);
        }
    });
    updateTierDescription();
}

function onL1RadioChanged() {
    const l1Inputs = document.querySelectorAll('input[name="enable_l1"]');
    l1Inputs.forEach(input => {
        const card = input.closest('.l1-radio-card');
        if (card) {
            card.classList.toggle('active', input.checked);
        }
    });
}

function onModelChanged() {
    const modelSelect = $('#model-select');
    if (!modelSelect) return;
    const modelId = modelSelect.value;
    const model = state.models.find(m => m.id === modelId);

    const hint = $('#model-hint');
    if (hint && model) {
        hint.textContent = model.description || '';
    }

    const disableCard = $('#l1-card-disable');
    const disableInput = disableCard ? disableCard.querySelector('input') : null;
    const enableCard = $('#l1-card-enable');
    const enableInput = enableCard ? enableCard.querySelector('input') : null;

    if (modelId === 'l1-rules') {
        if (disableCard) disableCard.classList.add('disabled');
        if (disableInput) disableInput.disabled = true;
        if (enableInput) enableInput.checked = true;
        if (enableCard) enableCard.classList.add('active');
        if (disableCard) disableCard.classList.remove('active');
        if (hint) hint.textContent = 'L1 Declarative Static Rule Engine (<0.2ms regex/DLP).';
    } else {
        if (disableCard) disableCard.classList.remove('disabled');
        if (disableInput) disableInput.disabled = false;
    }
}

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

    if (state.datasets.length > 0) {
        select.value = state.datasets[0].id;
        const ds = state.datasets[0];
        const hint = $('#dataset-hint');
        if (hint) {
            hint.textContent = `${ds.rows.toLocaleString()} satır · ${ds.size_kb} KB · ${ds.filename}`;
        }
        updateTierCounts(ds);
    }
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

    if (state.models.length > 0) {
        select.selectedIndex = 0;
        onModelChanged();
    }
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
    const l1Decided = (data.case_results || []).filter(c => c.decided_by === 'L1').length;
    const casesCount = (data.case_results || []).length;

    const metricsHtml = [
        { label: 'Accuracy', value: data.accuracy, suffix: '%' },
        { label: 'Precision', value: data.precision, suffix: '%' },
        { label: 'Recall', value: data.recall, suffix: '%' },
        { label: 'F1 Score', value: data.f1, suffix: '%' },
        { label: 'FPR', value: data.fpr, suffix: '%' },
        ...(l1Decided > 0 && casesCount > 0 ? [
            { label: '⚡ L1 Offload', value: Math.round((l1Decided / casesCount) * 100), suffix: '%' }
        ] : []),
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
            <td>${c.predicted_blocked ? '🛑 Blocked' : '✅ Allowed'}${c.decided_by ? ` <span style="font-size:0.75rem; font-weight:600; padding:1px 5px; border-radius:4px; background:${c.decided_by==='L1'?'rgba(245,158,11,0.15)':'rgba(59,130,246,0.15)'}; color:${c.decided_by==='L1'?'#f59e0b':'#3b82f6'}">${c.decided_by}</span>` : ''}</td>
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
            ${c.decided_by ? `
            <div class="case-meta-chip">
                <span class="case-meta-label">Decided By</span>
                <span class="case-meta-value mono font-semibold" style="color: ${c.decided_by === 'L1' ? '#f59e0b' : '#3b82f6'};">
                    ${c.decided_by === 'L1' ? '⚡ L1 Static' : '🍎 L2 MLX'}
                </span>
            </div>` : ''}
            ${c.offload_saved_ms ? `
            <div class="case-meta-chip">
                <span class="case-meta-label">Offload Saved</span>
                <span class="case-meta-value mono" style="color: #10b981; font-weight: 600;">~${c.offload_saved_ms}ms</span>
            </div>` : ''}
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

    const overlay = $('#drawer-overlay');
    if (overlay) overlay.classList.add('active');
    detail.classList.add('open');
}

function closeCaseDetail(updateHash = true) {
    const detail = $('#case-detail-drawer');
    const overlay = $('#drawer-overlay');
    if (detail) detail.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    state.testCases.activeCaseId = null;
    state.testCases.activeCasePayload = null;

    if (updateHash && state.currentPage === 'test-cases') {
        updateUrlHash(false);
    }
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

// ─── Compare Runs Logic ───────────────────────────────────────────────────

state.compareData = null;
state.currentDiscrepancies = [];
state.compareFilter = 'all';

function populateCompareSelects() {
    const selA = $('#compare-run-a-select');
    const selB = $('#compare-run-b-select');
    if (!selA || !selB) return;

    const completed = (state.runs || []).filter(r => r.status === 'completed');
    if (completed.length === 0) {
        selA.innerHTML = '<option value="">Tamamlanmış koşum bulunamadı</option>';
        selB.innerHTML = '<option value="">Tamamlanmış koşum bulunamadı</option>';
        return;
    }

    // Group runs by dataset
    const datasets = {};
    completed.forEach(r => {
        const ds = r.dataset_name || 'Diğer';
        if (!datasets[ds]) datasets[ds] = [];
        datasets[ds].push(r);
    });

    let htmlA = '<option value="">Run A seçin (Baseline)...</option>';
    for (const [dsName, runs] of Object.entries(datasets)) {
        htmlA += `<optgroup label="Dataset: ${dsName} (${runs.length} koşum)">`;
        runs.forEach(r => {
            const dt = r.started_at ? new Date(r.started_at).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }) : '';
            htmlA += `<option value="${r.run_id}">${r.model_name} (${r.run_id}, F1: ${r.f1 || 0}%, ${dt})</option>`;
        });
        htmlA += `</optgroup>`;
    }
    selA.innerHTML = htmlA;

    // Pick a default dataset that has >= 2 runs for immediate comparison readiness
    let defaultRunA = null;
    for (const runs of Object.values(datasets)) {
        if (runs.length >= 2) {
            defaultRunA = runs[0].run_id;
            break;
        }
    }
    if (!defaultRunA && completed.length > 0) {
        defaultRunA = completed[0].run_id;
    }

    if (defaultRunA) {
        selA.value = defaultRunA;
    }

    onCompareRunAChanged();
}

function onCompareRunAChanged() {
    const selA = $('#compare-run-a-select');
    const selB = $('#compare-run-b-select');
    const btn = $('#btn-compare-execute');
    if (!selA || !selB) return;

    const runAId = selA.value;
    if (!runAId) {
        selB.innerHTML = '<option value="">Önce Run A seçin...</option>';
        selB.disabled = true;
        if (btn) btn.disabled = true;
        return;
    }

    const runA = (state.runs || []).find(r => r.run_id === runAId);
    if (!runA) return;

    const targetDataset = runA.dataset_name;

    // Filter candidates strictly to the SAME dataset and different run_id
    const candidates = (state.runs || []).filter(r =>
        r.status === 'completed' &&
        r.dataset_name === targetDataset &&
        r.run_id !== runAId
    );

    if (candidates.length === 0) {
        selB.innerHTML = `<option value="">Bu dataset (${targetDataset}) için karşılaştırılacak başka model yok</option>`;
        selB.disabled = true;
        if (btn) btn.disabled = true;
        return;
    }

    selB.disabled = false;
    if (btn) btn.disabled = false;

    selB.innerHTML = candidates.map(r => {
        const dt = r.started_at ? new Date(r.started_at).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }) : '';
        return `<option value="${r.run_id}">${r.model_name} (${r.run_id}, F1: ${r.f1 || 0}%, ${dt})</option>`;
    }).join('');

    selB.selectedIndex = 0;
}

async function executeComparison() {
    const selA = $('#compare-run-a-select');
    const selB = $('#compare-run-b-select');
    const runA = selA ? selA.value : '';
    const runB = selB ? selB.value : '';

    if (!runA || !runB) {
        showToast('Lütfen karşılaştırmak için iki koşum seçin.', 'warn');
        return;
    }

    const btn = $('#btn-compare-execute');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '⏳ Hesaplanıyor...';
    }

    try {
        const res = await fetch(`/api/runs/${runA}/compare/${runB}?filter=all&limit=250`);
        const data = await res.json();
        if (data.error) {
            showToast(data.error, 'error');
            return;
        }

        state.compareData = data;
        state.compareFilter = 'all';
        renderComparisonResults(data);
        showToast(`Karşılaştırma tamamlandı: ${data.agreement_stats.discrepant_verdicts} zıt karar bulundu.`, 'info');
    } catch (e) {
        showToast(`Karşılaştırma hatası: ${e.message}`, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '⚡ Karşılaştır';
        }
    }
}

function renderComparisonResults(data) {
    const container = $('#compare-results-container');
    if (!container) return;
    container.style.display = 'block';

    const rA = data.run_a;
    const rB = data.run_b;
    const ast = data.agreement_stats;

    // Header info
    setText('#compare-model-a-title', rA.model_name);
    setText('#compare-run-a-id', rA.run_id);
    setText('#compare-model-b-title', rB.model_name);
    setText('#compare-run-b-id', rB.run_id);
    setText('#compare-dataset-badge', `Dataset: ${rA.dataset_name} (${ast.total_common} ortak vaka)`);

    const thA = $('#th-model-a');
    const thB = $('#th-model-b');
    if (thA) thA.textContent = `${rA.model_name}`;
    if (thB) thB.textContent = `${rB.model_name}`;

    // Calculate deltas
    const f1Delta = (rB.f1 - rA.f1).toFixed(1);
    const f1DeltaPrefix = f1Delta > 0 ? '+' : '';
    const latDelta = (rB.avg_latency_ms - rA.avg_latency_ms).toFixed(2);
    const latDeltaPrefix = latDelta > 0 ? '+' : '';

    // Macro metric cards
    const metricsHtml = [
        { label: 'Mutabakat Oranı', value: ast.agreement_rate_pct, suffix: '%', cls: ast.agreement_rate_pct >= 80 ? 'good' : 'warn' },
        { label: 'Ayrışan Kararlar', value: ast.discrepant_verdicts, suffix: ' vaka', cls: ast.discrepant_verdicts === 0 ? 'good' : 'info' },
        { label: 'F1 Skoru Farkı (B - A)', value: `${f1DeltaPrefix}${f1Delta}`, suffix: '%', cls: f1Delta >= 0 ? 'good' : 'bad' },
        { label: 'Ort. Gecikme Farkı (B - A)', value: `${latDeltaPrefix}${latDelta}`, suffix: 'ms', cls: latDelta <= 0 ? 'good' : 'warn' },
        { label: 'A Kaçırdı ➔ B Yakaladı', value: ast.a_missed_b_caught, suffix: ' vaka', cls: 'good' },
        { label: 'B Kaçırdı ➔ A Yakaladı', value: ast.b_missed_a_caught, suffix: ' vaka', cls: 'bad' },
    ].map(m => `
        <div class="metric-card">
            <div class="metric-label">${m.label}</div>
            <div class="metric-value ${m.cls}">${m.value}<span class="metric-suffix">${m.suffix}</span></div>
        </div>
    `).join('');

    $('#compare-metrics-grid').innerHTML = metricsHtml;

    // Filter counters
    setText('#count-disc-all', ast.discrepant_verdicts);
    setText('#count-disc-b-better', ast.a_missed_b_caught);
    setText('#count-disc-a-better', ast.b_missed_a_caught);
    setText('#count-disc-fp', (ast.discrepant_verdicts - ast.a_missed_b_caught - ast.b_missed_a_caught));

    // Render discrepancy rows
    renderDiscrepancyRows(data.discrepancies || []);
}

function renderDiscrepancyRows(discrepancies) {
    state.currentDiscrepancies = discrepancies;
    const tbody = $('#discrepancy-tbody');
    if (!tbody) return;

    if (discrepancies.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="padding: 30px; text-align: center; color: var(--text-tertiary);">
            Bu filtre için herhangi bir uyuşmazlık bulunamadı. İki model bu vakalarda tamamen mutabık!
        </td></tr>`;
        return;
    }

    tbody.innerHTML = discrepancies.map((d, idx) => {
        const aBlocked = d.run_a.predicted_blocked;
        const bBlocked = d.run_b.predicted_blocked;
        const aClass = d.run_a.correct ? 'case-correct' : 'case-incorrect';
        const bClass = d.run_b.correct ? 'case-correct' : 'case-incorrect';

        const latDiff = d.latency_diff_ms;
        const latDiffStr = (latDiff > 0 ? `+${latDiff}` : `${latDiff}`) + 'ms';
        const latClass = latDiff > 0 ? 'text-amber-400' : 'text-emerald-400';

        return `
            <tr class="case-row" onclick="showDiscrepancyDetail(${idx})" title="Tıkla: detaylı karşılaştırmayı ve payload'u gör">
                <td class="mono font-semibold">${d.case_id}</td>
                <td><span class="badge-domain">${d.domain}</span></td>
                <td><span class="mono text-xs" style="color: #818cf8;">${d.analysis_tier}</span></td>
                <td>${d.is_malicious ? '🔴 Zararlı' : '🟢 Meşru'}</td>
                <td>
                    <span class="${aClass}" style="font-weight: 600;">${aBlocked ? '🛑 Blocked' : '✅ Allowed'}</span>
                    <span class="mono text-xs" style="opacity: 0.7;">(${d.run_a.decided_by})</span>
                </td>
                <td>
                    <span class="${bClass}" style="font-weight: 600;">${bBlocked ? '🛑 Blocked' : '✅ Allowed'}</span>
                    <span class="mono text-xs" style="opacity: 0.7;">(${d.run_b.decided_by})</span>
                </td>
                <td class="mono text-sm ${latClass}">${latDiffStr}</td>
                <td class="case-expand-icon">▸</td>
            </tr>
        `;
    }).join('');
}

async function filterDiscrepancies(filterType) {
    if (!state.compareData) return;
    state.compareFilter = filterType;

    $$('.case-filters button[data-compare-filter]').forEach(b => {
        b.classList.toggle('active', b.dataset.compareFilter === filterType);
    });

    const runA = state.compareData.run_a.run_id;
    const runB = state.compareData.run_b.run_id;

    try {
        const res = await fetch(`/api/runs/${runA}/compare/${runB}?filter=${filterType}&limit=250`);
        const data = await res.json();
        renderDiscrepancyRows(data.discrepancies || []);
    } catch (e) {
        showToast(`Filtreleme hatası: ${e.message}`, 'error');
    }
}

function showDiscrepancyDetail(idx) {
    const d = state.currentDiscrepancies[idx];
    if (!d || !state.compareData) return;

    const detail = $('#case-detail-drawer');
    if (!detail) return;

    const rA = state.compareData.run_a;
    const rB = state.compareData.run_b;

    detail.innerHTML = `
        <div class="case-detail-header">
            <div class="case-detail-title">
                <span style="font-size: 1.2rem;">⚖️</span>
                <span>${d.case_id}</span>
            </div>
            <button class="modal-close" onclick="closeCaseDetail()">✕</button>
        </div>

        <div class="case-detail-meta">
            <div class="case-meta-chip">
                <span class="case-meta-label">Source</span>
                <span class="case-meta-value">${d.source || '—'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Domain</span>
                <span class="case-meta-value">${d.domain}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Tier</span>
                <span class="case-meta-value mono" style="color: #6366f1; font-weight: 600;">${d.analysis_tier}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">CWE</span>
                <span class="case-meta-value">${d.cwe || '—'}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Tool</span>
                <span class="case-meta-value mono">${d.tool_name}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Expected</span>
                <span class="case-meta-value font-semibold">${d.is_malicious ? '🔴 Zararlı (Block)' : '🟢 Meşru (Allow)'}</span>
            </div>
        </div>

        <!-- Side-by-Side Model Comparison -->
        <div style="margin-top: var(--space-4); margin-bottom: var(--space-4);">
            <div class="case-section-title" style="margin-bottom: var(--space-2);">⚔️ Model Karşılaştırması</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3);">
                <!-- Model A Card -->
                <div style="padding: 12px; border-radius: var(--radius-md); background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25);">
                    <div class="font-bold text-xs" style="color: #f59e0b; margin-bottom: 6px; text-transform: uppercase;">Run A: ${rA.model_name}</div>
                    <div style="font-size: 1.1rem; font-weight: bold; margin-bottom: 4px;">
                        ${d.run_a.predicted_blocked ? '🛑 BLOCKED' : '✅ ALLOWED'}
                        <span>${d.run_a.correct ? '✓' : '✕'}</span>
                    </div>
                    <div class="text-xs mono text-muted">Motor: ${d.run_a.decided_by}</div>
                    <div class="text-xs mono text-muted">Gecikme: ${d.run_a.latency_ms}ms</div>
                    ${d.run_a.verdict_detail ? `<div class="text-xs mono" style="margin-top: 4px; color: var(--text-secondary);">${escapeHtml(d.run_a.verdict_detail)}</div>` : ''}
                </div>

                <!-- Model B Card -->
                <div style="padding: 12px; border-radius: var(--radius-md); background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.25);">
                    <div class="font-bold text-xs" style="color: #3b82f6; margin-bottom: 6px; text-transform: uppercase;">Run B: ${rB.model_name}</div>
                    <div style="font-size: 1.1rem; font-weight: bold; margin-bottom: 4px;">
                        ${d.run_b.predicted_blocked ? '🛑 BLOCKED' : '✅ ALLOWED'}
                        <span>${d.run_b.correct ? '✓' : '✕'}</span>
                    </div>
                    <div class="text-xs mono text-muted">Motor: ${d.run_b.decided_by}</div>
                    <div class="text-xs mono text-muted">Gecikme: ${d.run_b.latency_ms}ms</div>
                    ${d.run_b.verdict_detail ? `<div class="text-xs mono" style="margin-top: 4px; color: var(--text-secondary);">${escapeHtml(d.run_b.verdict_detail)}</div>` : ''}
                </div>
            </div>
        </div>

        ${d.context ? `
        <div class="case-detail-section">
            <div class="case-section-title">📋 Context</div>
            <div class="case-context-box">${escapeHtml(d.context)}</div>
        </div>` : ''}

        <div class="case-detail-section">
            <div class="flex items-center justify-between" style="margin-bottom: var(--space-2);">
                <div class="case-section-title" style="margin-bottom: 0;">📦 Tool Arguments (Payload)</div>
                <button class="copy-payload-btn" onclick="copyPayload(this)" title="Payload'ı panoya kopyala">📋 Kopyala</button>
            </div>
            <pre class="case-payload-box"><code>${syntaxHighlight(d.tool_arguments || '{}')}</code></pre>
        </div>
    `;

    detail.classList.add('open');
}

// ─── Navigation ─────────────────────────────────────────────────────────────

function activatePageUI(page) {
    state.currentPage = page;
    $$('.page').forEach(el => el.classList.remove('active'));
    $$('.nav-btn').forEach(el => el.classList.remove('active'));

    const pageEl = $(`#page-${page}`);
    if (pageEl) pageEl.classList.add('active');

    const navBtn = $(`.nav-btn[data-page="${page}"]`);
    if (navBtn) navBtn.classList.add('active');
}

function switchPage(page, updateHash = true) {
    activatePageUI(page);

    if (page === 'history') {
        loadRuns();
    } else if (page === 'compare') {
        loadRuns().then(() => populateCompareSelects());
    } else if (page === 'test-cases') {
        initTestCasesPage();
    }

    if (updateHash) {
        updateUrlHash(state.currentPage === 'test-cases' && !!state.testCases.activeCaseId);
    }
}

// ─── Test Cases Explorer (ISSUE-006 & ISSUE-007) ───────────────────────────

async function initTestCasesPage() {
    if (!state.testCases.filtersLoaded) {
        await loadTestCaseFilters();
    }
    if (!state.testCases.eventsBound) {
        bindTestCaseEvents();
    }
    syncTestCaseFilterControls();
    await loadTestCases();
}

async function loadTestCaseFilters() {
    try {
        const res = await fetch('/api/test-cases/filters');
        if (!res.ok) throw new Error('Failed to load test case filters');
        const data = await res.json();

        // Total cases
        const totalEl = $('#tc-total-count');
        if (totalEl) totalEl.textContent = data.total_pool_cases.toLocaleString();

        // Populate datasets
        const dsSelect = $('#tc-filter-dataset');
        if (dsSelect) {
            dsSelect.innerHTML = `<option value="all">All Datasets (${data.total_pool_cases.toLocaleString()})</option>`;
            data.datasets.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.name;
                opt.textContent = `${d.name} (${d.count.toLocaleString()})`;
                dsSelect.appendChild(opt);
            });
            if (state.testCases.dataset) dsSelect.value = state.testCases.dataset;
        }

        // Populate domains
        const domSelect = $('#tc-filter-domain');
        if (domSelect) {
            domSelect.innerHTML = '<option value="all">All Threat Domains</option>';
            data.threat_domains.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.name;
                opt.textContent = `${d.name} (${d.count.toLocaleString()})`;
                domSelect.appendChild(opt);
            });
            if (state.testCases.threat_domain) domSelect.value = state.testCases.threat_domain;
        }

        state.testCases.filtersLoaded = true;
    } catch (err) {
        console.error('[TestCases] Error loading filters:', err);
        showToast('Failed to load test case filters: ' + err.message, 'error');
    }
}

async function loadTestCases(updateHash = true) {
    const tbody = $('#tc-cases-tbody');
    if (tbody) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; padding: var(--space-8); color: var(--text-tertiary);">
                    <div style="display: flex; align-items: center; justify-content: center; gap: var(--space-2);">
                        <span class="inline-spinner" style="display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.2); border-top-color: var(--accent-indigo); border-radius: 50%; animation: spin 0.6s linear infinite;"></span>
                        <span>Loading test scenarios from DuckDB...</span>
                    </div>
                </td>
            </tr>
        `;
    }

    const tc = state.testCases;
    const params = new URLSearchParams({
        page: tc.page,
        limit: tc.limit,
        sort_by: tc.sortBy || 'id',
        sort_order: tc.sortOrder || 'asc',
    });
    if (tc.search && tc.search.trim()) params.set('search', tc.search.trim());
    if (tc.dataset !== 'all') params.set('dataset', tc.dataset);
    if (tc.threat_domain !== 'all') params.set('threat_domain', tc.threat_domain);
    if (tc.tier !== 'all') params.set('tier', tc.tier);
    if (tc.status !== 'all') params.set('status', tc.status);

    try {
        const res = await fetch(`/api/test-cases?${params.toString()}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        tc.cases = data.cases || [];
        tc.total = data.pagination.total_records || 0;
        tc.totalPages = data.pagination.total_pages || 1;
        tc.page = data.pagination.page || 1;

        renderTestCasesTable();
        renderTestCasesPagination();
        updateTestCaseSortHeaders();

        const searchClear = $('#tc-search-clear');
        if (searchClear) {
            searchClear.style.display = tc.search ? 'block' : 'none';
        }

        if (updateHash) {
            updateUrlHash(state.currentPage === 'test-cases' && !!state.testCases.activeCaseId);
        }
    } catch (err) {
        console.error('[TestCases] Error loading cases:', err);
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; padding: var(--space-8); color: var(--color-danger);">
                        ❌ Failed to load test cases: ${escapeHtml(err.message)}
                    </td>
                </tr>
            `;
        }
        showToast('Failed to load test cases: ' + err.message, 'error');
    }
}

function renderTestCasesTable() {
    const tbody = $('#tc-cases-tbody');
    if (!tbody) return;

    const filteredEl = $('#tc-filtered-count');
    if (filteredEl) filteredEl.textContent = state.testCases.total.toLocaleString();

    if (state.testCases.cases.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; padding: var(--space-8);">
                    <div style="display: flex; flex-direction: column; align-items: center; gap: var(--space-3);">
                        <span style="font-size: 2.2rem; opacity: 0.6;">🛡️</span>
                        <div class="font-bold" style="color: var(--text-primary); font-size: 1rem;">No test cases found</div>
                        <div class="text-sm text-muted">No test scenarios match the current filter selection.</div>
                        <button class="btn btn-secondary btn-sm" onclick="resetTestCaseFilters()" style="margin-top: var(--space-2);">
                            ✕ Clear Filters
                        </button>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = state.testCases.cases.map(c => {
        const statusBadge = c.is_malicious
            ? '<span class="tc-status-badge tc-status-threat">🚨 Threat</span>'
            : '<span class="tc-status-badge tc-status-safe">🛡️ Safe</span>';

        let tierClass = 'tc-tier-static';
        let tierLabel = '⚡ Static';
        if (c.analysis_tier === 'SEMANTIC_REQUIRED') {
            tierClass = 'tc-tier-semantic';
            tierLabel = '🧠 Semantic';
        } else if (c.analysis_tier === 'HYBRID') {
            tierClass = 'tc-tier-hybrid';
            tierLabel = '🔀 Hybrid';
        }

        const safeId = escapeHtml(c.id);
        const safeDataset = escapeHtml(c.source_dataset || '—');
        const safeDomain = escapeHtml(c.threat_domain || '—');
        const safeTool = escapeHtml(c.tool_name || '—');

        return `
            <tr class="case-row" onclick="showTestCaseDetail('${safeId}')">
                <td>
                    <span class="mono font-bold" style="color: var(--accent-cyan); font-size: 0.82rem;">${safeId}</span>
                </td>
                <td>
                    <span class="badge" style="background: rgba(255,255,255,0.06); font-size: 0.72rem; color: var(--text-secondary);">${safeDataset}</span>
                </td>
                <td>
                    <span class="badge badge-domain">${safeDomain}</span>
                </td>
                <td>
                    <span class="tc-tier-badge ${tierClass}">${tierLabel}</span>
                </td>
                <td>${statusBadge}</td>
                <td>
                    <span class="mono text-xs" style="color: var(--text-primary);">${safeTool}</span>
                </td>
                <td style="text-align: right;">
                    <button class="btn btn-sm btn-secondary copy-payload-btn" style="padding: 2px 8px;" onclick="event.stopPropagation(); showTestCaseDetail('${safeId}')">
                        👁️ View
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function renderTestCasesPagination() {
    const tc = state.testCases;
    const start = tc.total === 0 ? 0 : (tc.page - 1) * tc.limit + 1;
    const end = Math.min(tc.total, tc.page * tc.limit);

    setText('#tc-pagination-info', `Showing ${start.toLocaleString()} - ${end.toLocaleString()} of ${tc.total.toLocaleString()} cases`);
    setText('#tc-current-page', tc.page);
    setText('#tc-total-pages', tc.totalPages);

    const btnFirst = $('#tc-page-first');
    const btnPrev = $('#tc-page-prev');
    const btnNext = $('#tc-page-next');
    const btnLast = $('#tc-page-last');

    if (btnFirst) btnFirst.disabled = tc.page <= 1;
    if (btnPrev) btnPrev.disabled = tc.page <= 1;
    if (btnNext) btnNext.disabled = tc.page >= tc.totalPages;
    if (btnLast) btnLast.disabled = tc.page >= tc.totalPages;
}

function updateTestCaseSortHeaders() {
    const tc = state.testCases;
    const headers = $$('th.tc-sortable');
    headers.forEach(th => {
        const col = th.getAttribute('data-sort');
        const icon = th.querySelector('.tc-sort-icon');
        th.classList.remove('sorted-asc', 'sorted-desc');
        if (col === tc.sortBy) {
            if (tc.sortOrder === 'desc') {
                th.classList.add('sorted-desc');
                if (icon) icon.textContent = '▼';
            } else {
                th.classList.add('sorted-asc');
                if (icon) icon.textContent = '▲';
            }
        } else {
            if (icon) icon.textContent = '⇅';
        }
    });
}

function bindTestCaseEvents() {
    const tc = state.testCases;

    const searchInput = $('#tc-search-input');
    const searchClear = $('#tc-search-clear');

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const val = e.target.value;
            tc.search = val;
            if (searchClear) searchClear.style.display = val ? 'block' : 'none';

            if (tc.searchDebounceTimer) clearTimeout(tc.searchDebounceTimer);
            tc.searchDebounceTimer = setTimeout(() => {
                tc.page = 1;
                loadTestCases(true);
            }, 300);
        });

        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                e.stopPropagation();
                if (searchInput.value) {
                    searchInput.value = '';
                    tc.search = '';
                    if (searchClear) searchClear.style.display = 'none';
                    tc.page = 1;
                    loadTestCases(true);
                }
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (tc.searchDebounceTimer) clearTimeout(tc.searchDebounceTimer);
                tc.page = 1;
                loadTestCases(true);
            }
        });
    }

    if (searchClear) {
        searchClear.addEventListener('click', () => {
            if (searchInput) searchInput.value = '';
            tc.search = '';
            searchClear.style.display = 'none';
            tc.page = 1;
            loadTestCases(true);
            if (searchInput) searchInput.focus();
        });
    }

    const sortHeaders = $$('th.tc-sortable');
    sortHeaders.forEach(th => {
        th.addEventListener('click', () => {
            const col = th.getAttribute('data-sort');
            if (!col) return;

            if (tc.sortBy === col) {
                tc.sortOrder = tc.sortOrder === 'asc' ? 'desc' : 'asc';
            } else {
                tc.sortBy = col;
                tc.sortOrder = 'asc';
            }
            tc.page = 1;
            loadTestCases(true);
        });
    });

    const dsSelect = $('#tc-filter-dataset');
    if (dsSelect) {
        dsSelect.addEventListener('change', () => {
            tc.dataset = dsSelect.value;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const domSelect = $('#tc-filter-domain');
    if (domSelect) {
        domSelect.addEventListener('change', () => {
            tc.threat_domain = domSelect.value;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const tierSelect = $('#tc-filter-tier');
    if (tierSelect) {
        tierSelect.addEventListener('change', () => {
            tc.tier = tierSelect.value;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const statusSelect = $('#tc-filter-status');
    if (statusSelect) {
        statusSelect.addEventListener('change', () => {
            tc.status = statusSelect.value;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const limitSelect = $('#tc-filter-limit');
    if (limitSelect) {
        limitSelect.addEventListener('change', () => {
            tc.limit = parseInt(limitSelect.value, 10) || 50;
            tc.page = 1;
            loadTestCases(true);
        });
    }

    const resetBtn = $('#tc-btn-reset');
    if (resetBtn) {
        resetBtn.addEventListener('click', resetTestCaseFilters);
    }

    const btnFirst = $('#tc-page-first');
    if (btnFirst) {
        btnFirst.addEventListener('click', () => {
            if (tc.page > 1) {
                tc.page = 1;
                loadTestCases(true);
            }
        });
    }

    const btnPrev = $('#tc-page-prev');
    if (btnPrev) {
        btnPrev.addEventListener('click', () => {
            if (tc.page > 1) {
                tc.page--;
                loadTestCases(true);
            }
        });
    }

    const btnNext = $('#tc-page-next');
    if (btnNext) {
        btnNext.addEventListener('click', () => {
            if (tc.page < tc.totalPages) {
                tc.page++;
                loadTestCases(true);
            }
        });
    }

    const btnLast = $('#tc-page-last');
    if (btnLast) {
        btnLast.addEventListener('click', () => {
            if (tc.page < tc.totalPages) {
                tc.page = tc.totalPages;
                loadTestCases(true);
            }
        });
    }

    state.testCases.eventsBound = true;
}

function resetTestCaseFilters() {
    const tc = state.testCases;
    tc.dataset = 'all';
    tc.threat_domain = 'all';
    tc.tier = 'all';
    tc.status = 'all';
    tc.search = '';
    tc.sortBy = 'id';
    tc.sortOrder = 'asc';
    tc.page = 1;

    const searchInput = $('#tc-search-input');
    if (searchInput) searchInput.value = '';

    const searchClear = $('#tc-search-clear');
    if (searchClear) searchClear.style.display = 'none';

    const dsSelect = $('#tc-filter-dataset');
    if (dsSelect) dsSelect.value = 'all';

    const domSelect = $('#tc-filter-domain');
    if (domSelect) domSelect.value = 'all';

    const tierSelect = $('#tc-filter-tier');
    if (tierSelect) tierSelect.value = 'all';

    const statusSelect = $('#tc-filter-status');
    if (statusSelect) statusSelect.value = 'all';

    loadTestCases(true);
}

async function showTestCaseDetail(caseId, updateHash = true) {
    if (!caseId) return;

    const detail = $('#case-detail-drawer');
    const overlay = $('#drawer-overlay');
    if (!detail) return;

    state.testCases.activeCaseId = caseId;
    if (updateHash) {
        updateUrlHash(true);
    }

    if (overlay) overlay.classList.add('active');
    detail.classList.add('open');

    let c = (state.testCases.cases || []).find(item => item.id === caseId);

    if (!c) {
        // Skeleton loader while fetching single case
        detail.innerHTML = `
            <div class="case-detail-header">
                <div class="case-detail-title">
                    <span class="mono" style="color: var(--accent-cyan); font-weight: 700;">${escapeHtml(caseId)}</span>
                </div>
                <button class="modal-close" onclick="closeCaseDetail()" title="Close (Esc)">✕</button>
            </div>
            <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: var(--space-12); gap: var(--space-3); color: var(--text-tertiary);">
                <span class="inline-spinner" style="display: inline-block; width: 24px; height: 24px; border: 3px solid rgba(255,255,255,0.2); border-top-color: var(--accent-cyan); border-radius: 50%; animation: spin 0.6s linear infinite;"></span>
                <div style="font-size: 0.85rem;">Loading test scenario details...</div>
            </div>
        `;

        try {
            const res = await fetch(`/api/test-cases/${encodeURIComponent(caseId)}`);
            if (!res.ok) {
                throw new Error(res.status === 404 ? `Test case "${caseId}" not found in benchmark pool.` : `Server error (${res.status})`);
            }
            c = await res.json();
        } catch (err) {
            detail.innerHTML = `
                <div class="case-detail-header">
                    <div class="case-detail-title">
                        <span class="mono" style="color: var(--color-danger); font-weight: 700;">Not Found</span>
                    </div>
                    <button class="modal-close" onclick="closeCaseDetail()" title="Close (Esc)">✕</button>
                </div>
                <div style="padding: var(--space-8); text-align: center;">
                    <div style="font-size: 2.2rem; margin-bottom: var(--space-2);">⚠️</div>
                    <div style="color: var(--color-danger); font-weight: 600; margin-bottom: var(--space-2);">${escapeHtml(err.message)}</div>
                    <div class="text-sm text-muted" style="margin-bottom: var(--space-4);">The requested test case ID does not exist in master_benchmark.parquet.</div>
                    <button class="btn btn-secondary btn-sm" onclick="closeCaseDetail()">Close Drawer</button>
                </div>
            `;
            return;
        }
    }

    // Format tool arguments & pretty print JSON
    let prettyArgs = c.tool_arguments || '{}';
    let isJson = false;
    try {
        const parsed = typeof prettyArgs === 'string' ? JSON.parse(prettyArgs) : prettyArgs;
        prettyArgs = JSON.stringify(parsed, null, 2);
        isJson = true;
    } catch (_) {
        isJson = false;
    }
    state.testCases.activeCasePayload = prettyArgs;
    const highlightedPayload = isJson ? syntaxHighlight(prettyArgs) : escapeHtml(prettyArgs);

    const statusBadge = c.is_malicious
        ? '<span class="tc-status-badge tc-status-threat" style="font-size: 0.85rem; padding: 4px 10px;">🚨 Threat (Malicious)</span>'
        : '<span class="tc-status-badge tc-status-safe" style="font-size: 0.85rem; padding: 4px 10px;">🛡️ Safe (Benign)</span>';

    let tierBadgeColor = 'var(--color-success)';
    let tierIcon = '⚡';
    if (c.analysis_tier === 'SEMANTIC_REQUIRED') {
        tierBadgeColor = '#818cf8';
        tierIcon = '🧠';
    } else if (c.analysis_tier === 'HYBRID') {
        tierBadgeColor = '#fbbf24';
        tierIcon = '🔀';
    }

    detail.innerHTML = `
        <div class="case-detail-header">
            <div class="case-detail-title">
                <span class="mono" style="color: var(--accent-cyan); font-weight: 700; font-size: 1.05rem;">${escapeHtml(c.id)}</span>
            </div>
            <button class="modal-close" onclick="closeCaseDetail()" title="Close (Esc)">✕</button>
        </div>

        <div style="margin-bottom: var(--space-4); display: flex; align-items: center; justify-content: space-between;">
            ${statusBadge}
            <span class="mono text-xs text-muted">Direction: ${escapeHtml(c.traffic_direction || 'tools/call')}</span>
        </div>

        <div class="case-detail-meta" style="margin-bottom: var(--space-5);">
            <div class="case-meta-chip">
                <span class="case-meta-label">Dataset</span>
                <span class="case-meta-value">${escapeHtml(c.source_dataset || '—')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Threat Domain</span>
                <span class="case-meta-value">${escapeHtml(c.threat_domain || '—')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Analysis Tier</span>
                <span class="case-meta-value mono font-semibold" style="color: ${tierBadgeColor};">${tierIcon} ${escapeHtml(c.analysis_tier || 'STATIC_CAPABLE')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">CWE ID</span>
                <span class="case-meta-value mono">${escapeHtml(c.cwe || '—')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">OWASP LLM</span>
                <span class="case-meta-value mono">${escapeHtml(c.owasp_llm || '—')}</span>
            </div>
            <div class="case-meta-chip">
                <span class="case-meta-label">Target Tool</span>
                <span class="case-meta-value mono font-semibold" style="color: var(--accent-blue);">${escapeHtml(c.tool_name || '—')}</span>
            </div>
        </div>

        <!-- Prompt Context -->
        <div class="case-detail-section" style="margin-bottom: var(--space-5);">
            <div class="case-section-title">📋 Context / User Prompt</div>
            <div class="case-context-box" style="white-space: pre-wrap; font-size: 0.82rem; line-height: 1.6; max-height: 220px; overflow-y: auto;">${escapeHtml(c.context || 'No prompt context provided.')}</div>
        </div>

        <!-- Tool Arguments -->
        <div class="case-detail-section">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-2);">
                <div class="case-section-title" style="margin-bottom: 0;">📦 Tool Arguments (Payload)</div>
                <button class="copy-payload-btn" id="btn-copy-case-payload" onclick="copyTestCasePayload(this)" title="Copy payload to clipboard">📋 Copy</button>
            </div>
            <pre class="case-payload-box"><code id="tc-detail-payload-code">${highlightedPayload}</code></pre>
        </div>
    `;
}

function copyTestCasePayload(btn) {
    const payload = state.testCases.activeCasePayload || '';
    navigator.clipboard.writeText(payload).then(() => {
        btn.classList.add('copied');
        btn.textContent = '✓ Copied!';
        showToast('Payload copied to clipboard', 'info');
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.textContent = '📋 Copy';
        }, 1500);
    }).catch(err => {
        console.error('Clipboard copy failed:', err);
        showToast('Failed to copy to clipboard', 'error');
    });
}

// ─── URL Hash Deep-Linking (ISSUE-007) ──────────────────────────────────────

function updateUrlHash(includeCaseId = true) {
    if (state.currentPage !== 'test-cases') {
        const hash = `#${state.currentPage}`;
        if (window.location.hash !== hash) {
            history.replaceState(null, '', hash);
        }
        return;
    }

    const params = new URLSearchParams();
    const tc = state.testCases;

    if (tc.page && tc.page > 1) {
        params.set('page', tc.page);
    }
    if (tc.limit && tc.limit !== 50) {
        params.set('limit', tc.limit);
    }
    if (tc.dataset && tc.dataset !== 'all') {
        params.set('dataset', tc.dataset);
    }
    if (tc.threat_domain && tc.threat_domain !== 'all') {
        params.set('domain', tc.threat_domain);
    }
    if (tc.tier && tc.tier !== 'all') {
        params.set('tier', tc.tier);
    }
    if (tc.status && tc.status !== 'all') {
        params.set('status', tc.status);
    }
    if (tc.search && tc.search.trim()) {
        params.set('q', tc.search.trim());
    }
    if (tc.sortBy && tc.sortBy !== 'id') {
        params.set('sort_by', tc.sortBy);
    }
    if (tc.sortOrder && tc.sortOrder !== 'asc') {
        params.set('sort_order', tc.sortOrder);
    }
    if (includeCaseId && tc.activeCaseId) {
        params.set('id', tc.activeCaseId);
    }

    const qs = params.toString();
    const newHash = qs ? `#test-cases?${qs}` : '#test-cases';
    if (window.location.hash !== newHash) {
        history.replaceState(null, '', newHash);
    }
}

function parseHash() {
    const raw = window.location.hash.startsWith('#')
        ? window.location.hash.substring(1)
        : window.location.hash;

    if (!raw) return { page: 'dashboard', params: new URLSearchParams() };

    const qIdx = raw.indexOf('?');
    if (qIdx === -1) {
        return { page: raw, params: new URLSearchParams() };
    }

    const page = raw.substring(0, qIdx);
    const qs = raw.substring(qIdx + 1);
    return { page, params: new URLSearchParams(qs) };
}

let isNavigatingHash = false;
async function handleHashNavigation() {
    if (isNavigatingHash) return;
    isNavigatingHash = true;

    try {
        const { page, params } = parseHash();
        let targetPage = page;
        if (targetPage === 'benchmark') targetPage = 'dashboard';
        const validPages = ['dashboard', 'compare', 'test-cases', 'history'];
        if (!validPages.includes(targetPage)) {
            targetPage = 'dashboard';
        }

        if (targetPage === 'test-cases') {
            const pageNum = parseInt(params.get('page'), 10);
            state.testCases.page = (pageNum && pageNum > 0) ? pageNum : 1;

            const limitNum = parseInt(params.get('limit'), 10);
            state.testCases.limit = (limitNum && limitNum > 0) ? limitNum : 50;

            state.testCases.dataset = params.get('dataset') || 'all';
            state.testCases.threat_domain = params.get('domain') || params.get('threat_domain') || 'all';
            state.testCases.tier = params.get('tier') || 'all';
            state.testCases.status = params.get('status') || 'all';
            state.testCases.search = params.get('q') || params.get('search') || '';
            state.testCases.sortBy = params.get('sort_by') || 'id';
            state.testCases.sortOrder = (params.get('sort_order') || 'asc').toLowerCase() === 'desc' ? 'desc' : 'asc';

            const caseId = params.get('id');

            activatePageUI('test-cases');

            if (!state.testCases.filtersLoaded) {
                await loadTestCaseFilters();
            }
            if (!state.testCases.eventsBound) {
                bindTestCaseEvents();
            }
            syncTestCaseFilterControls();

            await loadTestCases(false);

            if (caseId) {
                await showTestCaseDetail(caseId, false);
            } else {
                closeCaseDetail(false);
            }
        } else {
            activatePageUI(targetPage);
            if (targetPage === 'history') {
                loadRuns();
            } else if (targetPage === 'compare') {
                loadRuns().then(() => populateCompareSelects());
            }
            closeCaseDetail(false);
        }
    } catch (err) {
        console.error('[HashNav] Error during hash navigation:', err);
    } finally {
        isNavigatingHash = false;
    }
}

function syncTestCaseFilterControls() {
    const searchInput = $('#tc-search-input');
    if (searchInput) searchInput.value = state.testCases.search || '';

    const searchClear = $('#tc-search-clear');
    if (searchClear) searchClear.style.display = state.testCases.search ? 'block' : 'none';

    const dsEl = $('#tc-filter-dataset');
    if (dsEl && state.testCases.dataset) dsEl.value = state.testCases.dataset;

    const domEl = $('#tc-filter-domain');
    if (domEl && state.testCases.threat_domain) domEl.value = state.testCases.threat_domain;

    const tierEl = $('#tc-filter-tier');
    if (tierEl && state.testCases.tier) tierEl.value = state.testCases.tier;

    const statusEl = $('#tc-filter-status');
    if (statusEl && state.testCases.status) statusEl.value = state.testCases.status;

    const limitEl = $('#tc-filter-limit');
    if (limitEl && state.testCases.limit) limitEl.value = String(state.testCases.limit);
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

    // Dataset select hint and tier counts update
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
            updateTierCounts(ds);
        });
    }

    // Model select change handler
    const modelSelect = $('#model-select');
    if (modelSelect) {
        modelSelect.addEventListener('change', onModelChanged);
    }

    // Tier scope radio change listeners
    document.querySelectorAll('input[name="tier_scope"]').forEach(r => {
        r.addEventListener('change', onTierRadioChanged);
    });

    // L1 Fail-fast radio change listeners
    document.querySelectorAll('input[name="enable_l1"]').forEach(r => {
        r.addEventListener('change', onL1RadioChanged);
    });

    // Deep-linking hash routing (ISSUE-007)
    window.addEventListener('hashchange', () => handleHashNavigation());
    if (window.location.hash) {
        handleHashNavigation();
    }

    // Global keyboard shortcuts (Escape key closes drawer & modal)
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' || e.key === 'Esc') {
            const drawer = $('#case-detail-drawer');
            if (drawer && drawer.classList.contains('open')) {
                closeCaseDetail();
            }
            const modal = $('#run-detail-modal');
            if (modal && modal.classList.contains('open')) {
                closeModal();
            }
        }
    });

    // WebSocket keepalive
    setInterval(() => {
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify({ type: 'ping' }));
        }
    }, 30000);
});
