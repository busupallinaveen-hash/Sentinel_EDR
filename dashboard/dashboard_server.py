#!/usr/bin/env python3
"""
dashboard/dashboard_server.py — SentinelEDR Web Dashboard

Lightweight HTTP dashboard server (no external web framework needed).
Uses Python's built-in http.server + threading.

Features:
  - Live alert feed (auto-refreshes every 5s)
  - Alert summary by severity + severity donut chart
  - 24h alert activity timeline (hourly, colored by peak severity)
  - MITRE ATT&CK tactic-column heatmap (all 14 tactics, color-scaled by volume)
  - Engine status panel
  - Response action log
  - Alert search + filter

Access at: http://localhost:8888
"""

import json, logging, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("SentinelEDR.Dashboard")

DASHBOARD_PORT = 8888
ROOT = Path(__file__).parent

# Make sibling packages (intel/, core/, etc.) importable regardless of how
# this file was launched — `python sentinel.py` (cwd = project root) already
# has them on sys.path, but `python dashboard/dashboard_server.py` only puts
# dashboard/ itself there, so intel.mitre_mapper would fail to import below.
_PROJECT_ROOT = str(ROOT.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


# ── HTML Template ─────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentinelEDR — Live Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --text2: #8b949e;
    --red: #ff6b6b; --orange: #ffa94d; --yellow: #ffd43b;
    --blue: #74c0fc; --green: #69db7c; --purple: #da77f2;
    --accent: #1f6feb;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; gap: 16px; position: sticky; top: 0; z-index: 100; }
  header h1 { font-size: 18px; font-weight: 600; color: var(--blue); }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .status-label { font-size: 12px; color: var(--text2); }
  .uptime { margin-left: auto; font-size: 12px; color: var(--text2); }
  .layout { display: grid; grid-template-columns: 240px 1fr; min-height: calc(100vh - 49px); }
  .sidebar { background: var(--bg2); border-right: 1px solid var(--border); padding: 16px; }
  .sidebar h3 { font-size: 11px; font-weight: 600; color: var(--text2); letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 12px; }
  .stat-card { background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 8px; }
  .stat-card .label { font-size: 11px; color: var(--text2); margin-bottom: 4px; }
  .stat-card .value { font-size: 24px; font-weight: 700; }
  .value.critical { color: var(--red); }
  .value.high     { color: var(--orange); }
  .value.medium   { color: var(--yellow); }
  .value.low      { color: var(--blue); }
  .value.total    { color: var(--text); }
  .engine-list { margin-top: 20px; }
  .engine-row { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 12px; }
  .engine-row:last-child { border: none; }
  .engine-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
  .engine-dot.on  { background: var(--green); }
  .engine-dot.off { background: var(--text2); }
  .main { padding: 20px; overflow: auto; }
  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .section-header h2 { font-size: 15px; font-weight: 600; }
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { padding: 4px 12px; border-radius: 20px; border: 1px solid var(--border); background: var(--bg3); color: var(--text2); cursor: pointer; font-size: 12px; transition: all 0.15s; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--text); background: rgba(31,111,235,0.15); }
  .search-box { flex: 1; min-width: 200px; padding: 4px 12px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg3); color: var(--text); font-size: 12px; outline: none; }
  .search-box:focus { border-color: var(--accent); }
  table { width: 100%; border-collapse: collapse; }
  th { font-size: 11px; font-weight: 600; color: var(--text2); text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 12px; vertical-align: top; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge.CRITICAL { background: rgba(255,107,107,0.2); color: var(--red); }
  .badge.HIGH     { background: rgba(255,169,77,0.2);  color: var(--orange); }
  .badge.MEDIUM   { background: rgba(255,212,59,0.2);  color: var(--yellow); }
  .badge.LOW      { background: rgba(116,192,252,0.2); color: var(--blue); }
  .badge.INFO     { background: rgba(139,148,158,0.2); color: var(--text2); }
  .mitre-tag { background: rgba(218,119,242,0.15); color: var(--purple); border-radius: 3px; padding: 1px 6px; font-size: 10px; font-family: monospace; }
  .engine-tag { background: rgba(31,111,235,0.15); color: var(--blue); border-radius: 3px; padding: 1px 6px; font-size: 10px; }
  .ts { color: var(--text2); font-family: monospace; white-space: nowrap; }
  .risk-bar-wrap { width: 60px; height: 4px; background: var(--bg3); border-radius: 2px; display: inline-block; vertical-align: middle; margin-left: 4px; }
  .risk-bar { height: 100%; border-radius: 2px; background: var(--green); }
  .no-alerts { text-align: center; padding: 60px 20px; color: var(--text2); }
  .refresh-indicator { font-size: 11px; color: var(--text2); }
  .tab-bar { display: flex; gap: 4px; margin-bottom: 16px; border-bottom: 1px solid var(--border); }
  .tab { padding: 8px 16px; cursor: pointer; font-size: 13px; color: var(--text2); border-bottom: 2px solid transparent; margin-bottom: -1px; }
  .tab.active { color: var(--text); border-color: var(--accent); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .resp-row { background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; display: flex; align-items: center; gap: 12px; }
  .resp-icon { font-size: 16px; }
  .resp-details { flex: 1; }
  .resp-action { font-weight: 600; font-size: 12px; }
  .resp-msg { font-size: 11px; color: var(--text2); margin-top: 2px; }

  /* Severity donut (sidebar) */
  .donut-wrap { display: flex; align-items: center; gap: 12px; margin: 4px 0 16px; }
  .donut { width: 72px; height: 72px; border-radius: 50%; flex-shrink: 0; background: var(--bg3); position: relative; }
  .donut::after { content: ''; position: absolute; inset: 12px; border-radius: 50%; background: var(--bg2); }
  .donut-legend { font-size: 11px; color: var(--text2); display: flex; flex-direction: column; gap: 3px; }
  .donut-legend span.sw { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 6px; }

  /* 24h activity timeline */
  .timeline-wrap { margin-bottom: 18px; }
  .timeline-bars { display: flex; align-items: flex-end; gap: 3px; height: 64px; border-bottom: 1px solid var(--border); padding-bottom: 2px; }
  .timeline-bar { flex: 1; min-width: 4px; border-radius: 2px 2px 0 0; background: var(--bg3); position: relative; transition: height 0.2s; }
  .timeline-bar:hover { outline: 1px solid var(--accent); }
  .timeline-labels { display: flex; justify-content: space-between; font-size: 10px; color: var(--text2); margin-top: 4px; }
  .timeline-bar[data-tip]:hover::after {
    content: attr(data-tip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%);
    background: var(--bg3); border: 1px solid var(--border); color: var(--text); font-size: 10px;
    padding: 3px 6px; border-radius: 4px; white-space: nowrap; margin-bottom: 4px; z-index: 10;
  }

  /* MITRE tactic-column heatmap */
  .mitre-heatmap { display: flex; gap: 6px; overflow-x: auto; padding-bottom: 10px; }
  .mitre-col { min-width: 132px; flex: 1; }
  .mitre-col-header { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;
    color: var(--text2); text-align: center; padding: 0 2px 8px; border-bottom: 2px solid var(--border); margin-bottom: 8px; }
  .mitre-cell { border-radius: 6px; padding: 8px 7px; margin-bottom: 6px; border: 1px solid var(--border); }
  .mitre-cell .tid { font-family: monospace; font-weight: 700; font-size: 11px; }
  .mitre-cell .tname { font-size: 9.5px; opacity: 0.85; margin-top: 2px; line-height: 1.3; }
  .mitre-cell .tcount { font-size: 10px; font-weight: 600; margin-top: 5px; }
  .mitre-empty-col { font-size: 10px; color: var(--text2); text-align: center; padding: 10px 0; opacity: 0.5; }
  .mitre-legend { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--text2); margin-bottom: 14px; }
  .mitre-legend .grad { width: 120px; height: 8px; border-radius: 4px;
    background: linear-gradient(90deg, #21262d, #5c2d2d, #b23b3b, #ff6b6b); }
</style>
</head>
<body>
<header>
  <div class="status-dot" id="statusDot"></div>
  <h1>⚔️ SentinelEDR</h1>
  <span class="status-label" id="statusLabel">Live</span>
  <span class="uptime" id="uptime"></span>
</header>
<div class="layout">
  <aside class="sidebar">
    <h3>Alert Summary</h3>
    <div class="donut-wrap">
      <div class="donut" id="severityDonut"></div>
      <div class="donut-legend">
        <div><span class="sw" style="background:var(--red)"></span>Critical</div>
        <div><span class="sw" style="background:var(--orange)"></span>High</div>
        <div><span class="sw" style="background:var(--yellow)"></span>Medium</div>
        <div><span class="sw" style="background:var(--blue)"></span>Low</div>
      </div>
    </div>
    <div class="stat-card"><div class="label">Total Alerts</div><div class="value total" id="totalCount">—</div></div>
    <div class="stat-card"><div class="label">Critical</div><div class="value critical" id="critCount">—</div></div>
    <div class="stat-card"><div class="label">High</div><div class="value high" id="highCount">—</div></div>
    <div class="stat-card"><div class="label">Medium</div><div class="value medium" id="medCount">—</div></div>
    <div class="stat-card"><div class="label">Low</div><div class="value low" id="lowCount">—</div></div>

    <div class="engine-list">
      <h3 style="margin-top:16px">Active Engines</h3>
      <div id="engineList">Loading...</div>
    </div>
  </aside>

  <main class="main">
    <div class="tab-bar">
      <div class="tab active" onclick="switchTab('alerts',this)">🚨 Live Alerts</div>
      <div class="tab" onclick="switchTab('responses',this)">⚡ Responses</div>
      <div class="tab" onclick="switchTab('mitre',this)">🗺 MITRE Coverage</div>
    </div>

    <!-- Alerts tab -->
    <div class="tab-content active" id="tab-alerts">
      <div class="section-header">
        <h2>Live Alert Feed</h2>
        <span class="refresh-indicator" id="refreshLabel">Auto-refresh: 5s</span>
      </div>
      <div class="timeline-wrap">
        <div class="timeline-bars" id="timelineBars"></div>
        <div class="timeline-labels" id="timelineLabels"></div>
      </div>
      <div class="filter-bar">
        <button class="filter-btn active" onclick="setFilter('ALL',this)">All</button>
        <button class="filter-btn" onclick="setFilter('CRITICAL',this)">🔴 Critical</button>
        <button class="filter-btn" onclick="setFilter('HIGH',this)">🟠 High</button>
        <button class="filter-btn" onclick="setFilter('MEDIUM',this)">🟡 Medium</button>
        <button class="filter-btn" onclick="setFilter('LOW',this)">🔵 Low</button>
        <input class="search-box" id="searchBox" placeholder="Search alerts..." oninput="renderTable()">
      </div>
      <table>
        <thead><tr>
          <th>Time</th><th>Severity</th><th>Engine</th><th>Alert</th>
          <th>MITRE</th><th>Risk</th>
        </tr></thead>
        <tbody id="alertBody"></tbody>
      </table>
      <div class="no-alerts" id="noAlerts" style="display:none">
        ✅ No alerts yet — SentinelEDR is monitoring
      </div>
    </div>

    <!-- Responses tab -->
    <div class="tab-content" id="tab-responses">
      <h2 style="margin-bottom:16px">Automated Response Actions</h2>
      <div id="responseList"><div class="no-alerts">No response actions taken yet.</div></div>
    </div>

    <!-- MITRE tab -->
    <div class="tab-content" id="tab-mitre">
      <div class="section-header">
        <h2>MITRE ATT&CK Coverage</h2>
      </div>
      <div class="mitre-legend">
        <span>Fewer alerts</span><div class="grad"></div><span>More alerts</span>
      </div>
      <div class="mitre-heatmap" id="mitreGrid"></div>
    </div>
  </main>
</div>

<script>
let allAlerts = [];
let activeFilter = 'ALL';
let startTime = Date.now();
let mitreCatalog = {};
let tacticOrder = [];

async function loadMitreCatalog() {
  try {
    const r = await fetch('/api/mitre/catalog');
    if (!r.ok) return;
    const data = await r.json();
    mitreCatalog = data.techniques || {};
    tacticOrder = data.tactic_order || [];
  } catch(e) {}
}

function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}

function setFilter(f, el) {
  activeFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  renderTable();
}

function renderTable() {
  const search = (document.getElementById('searchBox').value || '').toLowerCase();
  const filtered = allAlerts.filter(a => {
    const sevOk = activeFilter === 'ALL' || a.severity === activeFilter;
    const searchOk = !search || JSON.stringify(a).toLowerCase().includes(search);
    return sevOk && searchOk;
  });

  const tbody = document.getElementById('alertBody');
  const noAlerts = document.getElementById('noAlerts');

  if (filtered.length === 0) {
    tbody.innerHTML = '';
    noAlerts.style.display = 'block';
    return;
  }
  noAlerts.style.display = 'none';

  tbody.innerHTML = filtered.slice(0, 200).map(a => {
    const ts = (a.timestamp || '').slice(11, 19);
    const riskColor = a.risk_score >= 80 ? '#ff6b6b' : a.risk_score >= 60 ? '#ffa94d' : a.risk_score >= 40 ? '#ffd43b' : '#74c0fc';
    return `<tr>
      <td class="ts">${ts}</td>
      <td><span class="badge ${a.severity}">${a.severity}</span></td>
      <td><span class="engine-tag">${a.engine || 'core'}</span></td>
      <td>
        <div style="font-weight:500">${escHtml(a.title || '')}</div>
        <div style="color:var(--text2);font-size:11px;margin-top:2px">${escHtml((a.description || '').slice(0, 120))}${(a.description||'').length > 120 ? '…' : ''}</div>
      </td>
      <td>${a.mitre_tech ? `<span class="mitre-tag">${a.mitre_tech}</span>` : '—'}</td>
      <td>
        <span style="color:${riskColor};font-weight:600">${a.risk_score}</span>
        <div class="risk-bar-wrap"><div class="risk-bar" style="width:${a.risk_score}%;background:${riskColor}"></div></div>
      </td>
    </tr>`;
  }).join('');
}

function escHtml(s) {
  return (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function updateStats(alerts) {
  const counts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  alerts.forEach(a => { if (counts[a.severity] !== undefined) counts[a.severity]++; });
  document.getElementById('totalCount').textContent = alerts.length;
  document.getElementById('critCount').textContent = counts.CRITICAL;
  document.getElementById('highCount').textContent = counts.HIGH;
  document.getElementById('medCount').textContent = counts.MEDIUM;
  document.getElementById('lowCount').textContent = counts.LOW;
  renderDonut(counts);
}

function renderDonut(counts) {
  const donut = document.getElementById('severityDonut');
  const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
  if (total === 0) { donut.style.background = 'var(--bg3)'; return; }
  const colors = {CRITICAL:'#ff6b6b', HIGH:'#ffa94d', MEDIUM:'#ffd43b', LOW:'#74c0fc'};
  let acc = 0, stops = [];
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(sev => {
    if (!counts[sev]) return;
    const start = (acc / total) * 360;
    acc += counts[sev];
    const end = (acc / total) * 360;
    stops.push(`${colors[sev]} ${start}deg ${end}deg`);
  });
  donut.style.background = `conic-gradient(${stops.join(', ')})`;
}

function renderTimeline(alerts) {
  const HOURS = 24;
  const now = new Date();
  const buckets = Array.from({length: HOURS}, () => ({count: 0, maxSev: null}));
  const sevRank = {LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4, INFO:0};
  const sevColor = {LOW:'var(--blue)', MEDIUM:'var(--yellow)', HIGH:'var(--orange)', CRITICAL:'var(--red)', INFO:'var(--text2)'};
  const cutoff = now.getTime() - HOURS * 3600 * 1000;

  alerts.forEach(a => {
    const t = new Date(a.timestamp).getTime();
    if (isNaN(t) || t < cutoff) return;
    const idx = Math.min(HOURS - 1, Math.floor((t - cutoff) / (3600 * 1000)));
    const b = buckets[idx];
    b.count++;
    if (b.maxSev === null || (sevRank[a.severity]||0) > (sevRank[b.maxSev]||0)) b.maxSev = a.severity;
  });

  const maxCount = Math.max(1, ...buckets.map(b => b.count));
  const barsEl = document.getElementById('timelineBars');
  barsEl.innerHTML = buckets.map(b => {
    const h = b.count === 0 ? 2 : Math.max(4, Math.round((b.count / maxCount) * 60));
    const color = b.count === 0 ? 'var(--bg3)' : (sevColor[b.maxSev] || 'var(--blue)');
    const tip = b.count === 0 ? 'No alerts' : `${b.count} alert${b.count>1?'s':''} · ${b.maxSev}`;
    return `<div class="timeline-bar" data-tip="${tip}" style="height:${h}px;background:${color}"></div>`;
  }).join('');

  const labelsEl = document.getElementById('timelineLabels');
  labelsEl.innerHTML = ['-24h', '-18h', '-12h', '-6h', 'now'].map(l => `<span>${l}</span>`).join('');
}

function updateMitre(alerts) {
  const techniqueMap = {};
  alerts.forEach(a => {
    if (a.mitre_tech) techniqueMap[a.mitre_tech] = (techniqueMap[a.mitre_tech] || 0) + 1;
  });

  const grid = document.getElementById('mitreGrid');
  if (!tacticOrder.length) {
    grid.innerHTML = '<div style="color:var(--text2)">Loading MITRE catalog…</div>';
    return;
  }

  const maxCount = Math.max(1, ...Object.values(techniqueMap));
  const heatColor = (count) => {
    if (!count) return 'var(--bg3)';
    const ratio = count / maxCount;
    // interpolate bg3 (#21262d) -> red (#ff6b6b)
    const from = [0x21, 0x26, 0x2d], to = [0xff, 0x6b, 0x6b];
    const rgb = from.map((c, i) => Math.round(c + (to[i]-c) * ratio));
    return `rgb(${rgb.join(',')})`;
  };

  // group every known technique by tactic, so uncovered tactics still show as empty columns
  const byTactic = {};
  tacticOrder.forEach(t => byTactic[t] = []);
  Object.entries(mitreCatalog).forEach(([tid, meta]) => {
    if (!byTactic[meta.tactic]) byTactic[meta.tactic] = [];
    byTactic[meta.tactic].push({tid, name: meta.name, count: techniqueMap[tid] || 0});
  });

  grid.innerHTML = Object.keys(byTactic).map(tactic => {
    const techs = byTactic[tactic].sort((a,b) => b.count - a.count);
    const body = techs.length === 0
      ? '<div class="mitre-empty-col">—</div>'
      : techs.map(t => `
          <div class="mitre-cell" style="background:${heatColor(t.count)}">
            <div class="tid">${t.tid}</div>
            <div class="tname">${escHtml(t.name)}</div>
            ${t.count ? `<div class="tcount">${t.count} alert${t.count>1?'s':''}</div>` : ''}
          </div>`).join('');
    return `<div class="mitre-col"><div class="mitre-col-header">${escHtml(tactic)}</div>${body}</div>`;
  }).join('');
}

function updateEngines(engines) {
  document.getElementById('engineList').innerHTML = (engines||[]).map(e =>
    `<div class="engine-row"><div class="engine-dot on"></div><span>${e}</span></div>`
  ).join('') || '<div style="color:var(--text2);font-size:12px">Loading...</div>';
}

function updateUptime() {
  const s = Math.floor((Date.now() - startTime) / 1000);
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  document.getElementById('uptime').textContent =
    `Uptime: ${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
}

async function fetchData() {
  try {
    const [alertRes, statusRes] = await Promise.all([
      fetch('/api/alerts'),
      fetch('/api/status'),
    ]);
    if (alertRes.ok) {
      const data = await alertRes.json();
      allAlerts = (data.alerts || []).reverse();
      updateStats(allAlerts);
      renderTable();
      renderTimeline(allAlerts);
      updateMitre(allAlerts);
    }
    if (statusRes.ok) {
      const s = await statusRes.json();
      updateEngines(s.engines || []);
      if (s.start_time) startTime = s.start_time * 1000;
    }
    document.getElementById('statusDot').style.background = 'var(--green)';
    document.getElementById('statusLabel').textContent = 'Live';
  } catch(e) {
    document.getElementById('statusDot').style.background = 'var(--red)';
    document.getElementById('statusLabel').textContent = 'Disconnected';
  }
}

async function fetchResponses() {
  try {
    const r = await fetch('/api/responses');
    if (!r.ok) return;
    const data = await r.json();
    const actions = data.actions || [];
    const icons = {KILL_PROCESS:'💀', BLOCK_IP:'🚫', QUARANTINE_FILE:'🔒', COLLECT_FORENSICS:'🔍', default:'⚡'};
    document.getElementById('responseList').innerHTML = actions.length === 0
      ? '<div class="no-alerts">No response actions taken yet.</div>'
      : actions.slice().reverse().map(a => `
        <div class="resp-row">
          <span class="resp-icon">${icons[a.action]||icons.default}</span>
          <div class="resp-details">
            <div class="resp-action">${a.action}</div>
            <div class="resp-msg">${escHtml(a.message)} — <span style="color:var(--text2)">${(a.timestamp||'').slice(11,19)}</span></div>
          </div>
          <span style="color:${a.success?'var(--green)':'var(--red)'}">${a.success?'✅':'❌'}</span>
        </div>`).join('');
  } catch(e) {}
}

setInterval(updateUptime, 1000);
setInterval(fetchData, 5000);
setInterval(fetchResponses, 10000);
loadMitreCatalog().then(fetchData);
fetchResponses();
updateUptime();
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    orchestrator = None   # set by DashboardServer.start()

    def log_message(self, fmt, *args):
        pass  # suppress access logs

    def _json(self, data: dict, code: int = 200):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html: str):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == "/" or path == "/index.html":
            self._html(DASHBOARD_HTML)

        elif path == "/api/alerts":
            mgr = getattr(self.orchestrator, "alert_mgr", None)
            if mgr:
                alerts = [a.to_dict() for a in mgr.get_recent(500)]
            else:
                # Fallback: read from file
                alerts = self._read_alert_file()
            self._json({"alerts": alerts, "total": len(alerts)})

        elif path == "/api/status":
            orch   = self.orchestrator
            engines = list(getattr(orch, "_engines", {}).keys()) if orch else []
            start   = getattr(orch, "_start_time", time.time())
            mgr     = getattr(orch, "alert_mgr", None)
            stats   = mgr.get_stats() if mgr else {}
            self._json({
                "status":     "running",
                "engines":    engines,
                "start_time": start,
                "stats":      stats,
            })

        elif path == "/api/responses":
            orch = self.orchestrator
            resp_engine = (getattr(orch, "_engines", {}) or {}).get("ResponseEngine")
            actions = resp_engine.get_response_log() if resp_engine else []
            self._json({"actions": actions})

        elif path == "/api/mitre/catalog":
            from intel.mitre_mapper import technique_catalog, TACTIC_ORDER
            self._json({"techniques": technique_catalog(), "tactic_order": TACTIC_ORDER})

        elif path == "/api/export/mitre":
            from intel.mitre_mapper import export_navigator_heatmap
            mgr   = getattr(self.orchestrator, "alert_mgr", None)
            stats = mgr.get_stats() if mgr else {}
            out   = "/tmp/sentinel_mitre_export.json"
            export_navigator_heatmap(stats, out)
            self._json({"path": out, "message": "Exported successfully"})

        else:
            self.send_response(404)
            self.end_headers()

    def _read_alert_file(self):
        """Fallback: read alerts from JSON file if no orchestrator."""
        try:
            alert_file = "/tmp/sentinel_alerts.json"
            if os.path.exists(alert_file):
                with open(alert_file) as f:
                    return json.load(f)
        except Exception:
            pass
        return []


class DashboardServer:
    def __init__(self, port: int = DASHBOARD_PORT, orchestrator=None):
        self._port        = port
        self._orchestrator = orchestrator
        self._server      = None
        self._thread      = None

    def start(self):
        DashboardHandler.orchestrator = self._orchestrator

        self._server = HTTPServer(("0.0.0.0", self._port), DashboardHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="DashboardServer",
            daemon=True,
        )
        self._thread.start()
        log.info(f"Dashboard running at http://localhost:{self._port}")
        print(f"\n  🌐 Dashboard → http://localhost:{self._port}\n")

    def stop(self):
        if self._server:
            self._server.shutdown()


# ── Standalone mode ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    srv = DashboardServer(port=DASHBOARD_PORT)
    srv.start()
    print(f"Dashboard running at http://localhost:{DASHBOARD_PORT}")
    print("Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
